cmd_/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o := bfin-uclinux-gcc -Wp,-MD,/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/.crc-ccitt.o.d  -nostdinc -isystem /home/cvshdr/toolchain-new/uClinux/bfin-uclinux/bin/../lib/gcc/bfin-uclinux/3.4.6/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -ffreestanding -O2     -fomit-frame-pointer -Wdeclaration-after-statement  -Dlinux  -DSTANDALONE_ZAPATA -DEXPORT_SYMTAB   -DMODULE -mlong-calls -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(crc_ccitt)"  -D"KBUILD_MODNAME=KBUILD_STR(zaptel)" -c -o /home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o /home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.c

deps_/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o := \
  /home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.c \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
  include/linux/config.h \
    $(wildcard include/config/h.h) \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  include/linux/compiler.h \
  include/linux/compiler-gcc3.h \
  include/linux/compiler-gcc.h \
  include/asm/posix_types.h \
  include/asm/types.h \
  include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/kallsyms.h) \
  include/linux/sched.h \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/debug/mutexes.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/pm.h) \
  include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/linux/capability.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
  include/linux/thread_info.h \
  include/linux/bitops.h \
  include/asm/bitops.h \
  include/asm/byteorder.h \
  include/linux/byteorder/little_endian.h \
  include/linux/byteorder/swab.h \
  include/linux/byteorder/generic.h \
  include/asm/system.h \
    $(wildcard include/config/debug/hwerr.h) \
  include/linux/linkage.h \
  include/asm/linkage.h \
  include/asm/blackfin.h \
  include/asm/macros.h \
  include/asm/mach/blackfin.h \
  include/asm/mach/bf533.h \
    $(wildcard include/config/bf533.h) \
    $(wildcard include/config/bf532.h) \
    $(wildcard include/config/bank/1.h) \
    $(wildcard include/config/bank/0.h) \
    $(wildcard include/config/bank/3.h) \
    $(wildcard include/config/bank/2.h) \
    $(wildcard include/config/c/amben/all.h) \
    $(wildcard include/config/c/amben.h) \
    $(wildcard include/config/c/amben/b0.h) \
    $(wildcard include/config/c/amben/b0/b1.h) \
    $(wildcard include/config/c/amben/b0/b1/b2.h) \
    $(wildcard include/config/c/amcken.h) \
    $(wildcard include/config/c/cdprio.h) \
    $(wildcard include/config/bfin/kernel/clock.h) \
    $(wildcard include/config/vco/mult.h) \
    $(wildcard include/config/clkin/half.h) \
    $(wildcard include/config/vco/hz.h) \
    $(wildcard include/config/clkin/hz.h) \
    $(wildcard include/config/pll/bypass.h) \
    $(wildcard include/config/cclk/hz.h) \
    $(wildcard include/config/cclk/div.h) \
    $(wildcard include/config/sclk/hz.h) \
    $(wildcard include/config/sclk/div.h) \
    $(wildcard include/config/cclk/act/div.h) \
    $(wildcard include/config/cclk/div/not/defined/properly.h) \
    $(wildcard include/config/bf531.h) \
    $(wildcard include/config/mem/size.h) \
    $(wildcard include/config/blkfin/wt.h) \
    $(wildcard include/config/blkfin/wb.h) \
  include/asm/mach/mem_map.h \
    $(wildcard include/config/blkfin/cache.h) \
    $(wildcard include/config/blkfin/dcache.h) \
  include/asm/mach/defBF532.h \
  include/asm/mach-common/def_LPBlackfin.h \
  include/asm/mach/anomaly.h \
    $(wildcard include/config/bf/rev/0/4.h) \
    $(wildcard include/config/bf/rev/0/3.h) \
  include/asm/mach/anomaly.h \
  include/asm/mach/cdefBF532.h \
  include/asm/mach-common/cdef_LPBlackfin.h \
    $(wildcard include/config/bfin/alive/led.h) \
    $(wildcard include/config/bfin/alive/led/dport.h) \
    $(wildcard include/config/bfin/alive/led/port.h) \
    $(wildcard include/config/bfin/idle/led.h) \
    $(wildcard include/config/bfin/idle/led/dport.h) \
    $(wildcard include/config/bfin/idle/led/port.h) \
  include/asm/bfin-global.h \
  include/asm-generic/sections.h \
  include/asm/ptrace.h \
    $(wildcard include/config/binfmt/elf/fdpic.h) \
  include/asm/user.h \
  include/asm/page.h \
  include/asm/setup.h \
  include/asm/page_offset.h \
    $(wildcard include/config/bfin.h) \
  include/asm/io.h \
  include/asm-generic/page.h \
  include/asm/thread_info.h \
  include/asm/entry.h \
  include/asm/l1layout.h \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/printk.h) \
  /home/cvshdr/toolchain-new/uClinux/bfin-uclinux/bin/../lib/gcc/bfin-uclinux/3.4.6/include/stdarg.h \
  include/asm/bug.h \
    $(wildcard include/config/bug.h) \
  include/asm-generic/bug.h \
  include/linux/stringify.h \
  include/linux/spinlock_types.h \
  include/linux/spinlock_types_up.h \
  include/linux/spinlock_up.h \
  include/linux/spinlock_api_up.h \
  include/asm/atomic.h \
  include/asm-generic/atomic.h \
  include/asm/current.h \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/timex.h \
    $(wildcard include/config/time/interpolation.h) \
  include/linux/time.h \
  include/linux/seqlock.h \
  include/asm/timex.h \
  include/linux/jiffies.h \
  include/linux/calc64.h \
  include/asm/div64.h \
  include/asm-generic/div64.h \
  include/linux/rbtree.h \
  include/linux/cpumask.h \
  include/linux/bitmap.h \
  include/linux/string.h \
  include/asm/string.h \
  include/linux/errno.h \
  include/asm/errno.h \
  include/asm-generic/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/nodemask.h \
  include/linux/numa.h \
    $(wildcard include/config/flatmem.h) \
  include/asm/semaphore.h \
  include/linux/wait.h \
  include/linux/list.h \
  include/linux/prefetch.h \
  include/asm/processor.h \
  include/asm/segment.h \
  include/asm/cache.h \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/asm/mmu.h \
  include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/smp.h \
  include/linux/sem.h \
    $(wildcard include/config/sysvipc.h) \
  include/linux/ipc.h \
  include/asm/ipcbuf.h \
  include/asm/sembuf.h \
  include/linux/signal.h \
  include/asm/signal.h \
  include/asm/sigcontext.h \
  include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/securebits.h \
  include/linux/fs_struct.h \
  include/linux/completion.h \
  include/linux/pid.h \
  include/linux/percpu.h \
  include/linux/slab.h \
    $(wildcard include/config/.h) \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
  include/linux/gfp.h \
    $(wildcard include/config/dma/is/dma32.h) \
    $(wildcard include/config/np2/alloc.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/sparsemem.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
  include/linux/cache.h \
    $(wildcard include/config/x86.h) \
    $(wildcard include/config/sparc64.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/parisc.h) \
  include/linux/init.h \
    $(wildcard include/config/hotplug.h) \
  include/linux/memory_hotplug.h \
  include/linux/notifier.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
  include/asm/topology.h \
  include/asm-generic/topology.h \
  include/linux/kmalloc_sizes.h \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/large/allocs.h) \
  include/asm/percpu.h \
  include/asm-generic/percpu.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/linux/rcupdate.h \
  include/linux/auxvec.h \
  include/asm/auxvec.h \
  include/linux/param.h \
  include/linux/resource.h \
  include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/timer.h \
  include/linux/hrtimer.h \
    $(wildcard include/config/no/idle/hz.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/aio.h \
  include/linux/workqueue.h \
  include/linux/aio_abi.h \
  include/linux/stat.h \
  include/asm/stat.h \
  include/linux/kmod.h \
    $(wildcard include/config/kmod.h) \
  include/linux/elf.h \
  include/asm/elf.h \
  include/linux/kobject.h \
    $(wildcard include/config/net.h) \
  include/linux/sysfs.h \
    $(wildcard include/config/sysfs.h) \
  include/linux/kref.h \
  include/linux/moduleparam.h \
  include/asm/local.h \
  include/asm-generic/local.h \
  include/linux/hardirq.h \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/smp_lock.h \
    $(wildcard include/config/lock/kernel.h) \
  include/asm/hardirq.h \
  include/asm/irq.h \
  include/asm/mach/irq.h \
    $(wildcard include/config/irqchip/demux/gpio.h) \
  include/linux/irq_cpustat.h \
  include/asm/module.h \
  include/linux/crc-ccitt.h \

/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o: $(deps_/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o)

$(deps_/home/cvshdr/uclinux-outcvs/uClinux-dist/user/blkfin-apps/zaptel/crc-ccitt.o):
