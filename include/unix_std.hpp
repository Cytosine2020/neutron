#ifndef NEUTRON_UNIX_STD_HPP
#define NEUTRON_UNIX_STD_HPP


#define neutron_syscall_0(func) \
    this->set_x(IntRegT::A0, func())

#define neutron_syscall_1(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0)))

#define neutron_syscall_2(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                            this->get_x(IntRegT::A1)))

#define neutron_syscall_3(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2)))

#define neutron_syscall_4(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3)))

#define neutron_syscall_5(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3), \
                                  this->get_x(IntRegT::A4)))

#define neutron_syscall_6(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3), \
                                  this->get_x(IntRegT::A4), \
                                  this->get_x(IntRegT::A5)))

#define neutron_syscall(num, func) \
    neutron_syscall_##num(func)


#define __ARCH_WANT_NEW_STAT

namespace neutron {
    namespace syscall {
        enum syscall {
            io_setup = 0,
            io_destroy = 1,
            io_submit = 2,
            io_cancel = 3,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            io_getevents = 4,
#endif
            setxattr = 5, // fs/xattr.c
            lsetxattr = 6,
            fsetxattr = 7,
            getxattr = 8,
            lgetxattr = 9,
            fgetxattr = 10,
            listxattr = 11,
            llistxattr = 12,
            flistxattr = 13,
            removexattr = 14,
            lremovexattr = 15,
            fremovexattr = 16,
            getcwd = 17, // fs/dcache.c
            lookup_dcookie = 18, // fs/cookies.c
            eventfd2 = 19, // fs/eventfd.c
            epoll_create1 = 20, // fs/eventpoll.c
            epoll_ctl = 21,
            epoll_pwait = 22,
            dup = 23, // fs/fcntl.c
            dup3 = 24,
            fcntl = 25,
            inotify_init1 = 26, // fs/inotify_user.c 
            inotify_add_watch = 27,
            inotify_rm_watch = 28,
            ioctl = 29, // fs/ioctl.c
            ioprio_set = 30, // fs/ioprio.c 
            ioprio_get = 31,
            flock = 32, // fs/locks.c
            mknodat = 33, // fs/namei.c 
            mkdirat = 34,
            unlinkat = 35,
            symlinkat = 36,
            linkat = 37,
#ifdef __ARCH_WANT_RENAMEAT
            renameat = 38, // renameat is superseded with flags by renameat2 
#endif // __ARCH_WANT_RENAMEAT
            umount2 = 39, // fs/namespace.c 
            mount = 40,
            pivot_root = 41,
            nfsservctl = 42, // fs/nfsctl.c
            fstatfs = 44, // fs/open.c 
            truncate = 45,
            ftruncate = 46,
            fallocate = 47,
            faccessat = 48,
            chdir = 49,
            fchdir = 50,
            chroot = 51,
            fchmod = 52,
            fchmodat = 53,
            fchownat = 54,
            fchown = 55,
            openat = 56,
            close = 57,
            vhangup = 58,
            pipe2 = 59, // fs/pipe.c
            quotactl = 60, // fs/quota.c
            getdents64 = 61, // fs/readdir.c
            lseek = 62, // fs/read_write.c 
            read = 63,
            write = 64,
            readv = 65,
            writev = 66,
            pread64 = 67,
            pwrite64 = 68,
            preadv = 69,
            pwritev = 70,
            sendfile = 71, // fs/sendfile.c
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            pselect6 = 72, // fs/select.c 
            ppoll = 73,
#endif
            signalfd4 = 74, // fs/signalfd.c
            vmsplice = 75, // fs/splice.c 
            splice = 76,
            tee = 77,
            readlinkat = 78, // fs/stat.c 
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
            fstatat = 79,
            fstat = 80,
#endif
            sync = 81, // fs/sync.c 
            fsync = 82,
            fdatasync = 83,
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
            sync_file_range2 = 84,
#else
            sync_file_range = 84,
#endif
            timerfd_create = 85, // fs/timerfd.c 
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            timerfd_settime = 86,
            timerfd_gettime = 87,
#endif
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            utimensat = 88, // fs/utimes.c 
#endif
            acct = 89, // kernel/acct.c
            capget = 90, // kernel/capability.c 
            capset = 91,
            personality = 92, // kernel/exec_domain.c
            exit = 93, // kernel/exit.c
            exit_group = 94,
            waitid = 95,
            set_tid_address = 96, // kernel/fork.c 
            unshare = 97,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            futex = 98, // kernel/futex.c 
#endif
            set_robust_list = 99,
            get_robust_list = 100,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            nanosleep = 101, // kernel/hrtimer.c 
#endif
            getitimer = 102, // kernel/itimer.c 
            setitimer = 103,
            kexec_load = 104, // kernel/kexec.c
            init_module = 105, // kernel/module.c 
            delete_module = 106,
            timer_create = 107, // kernel/posix-timers.c
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            timer_gettime = 108,
#endif
            timer_getoverrun = 109,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            timer_settime = 110,
#endif
            timer_delete = 111,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            clock_settime = 112,
            clock_gettime = 113,
            clock_getres = 114,
            clock_nanosleep = 115,
#endif
            syslog = 116, // kernel/printk.c
            ptrace = 117, // kernel/ptrace.c
            sched_setparam = 118, // kernel/sched/core.c 
            sched_setscheduler = 119,
            sched_getscheduler = 120,
            sched_getparam = 121,
            sched_setaffinity = 122,
            sched_getaffinity = 123,
            sched_yield = 124,
            sched_get_priority_max = 125,
            sched_get_priority_min = 126,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            sched_rr_get_interval = 127,
#endif
            restart_syscall = 128, // kernel/signal.c 
            kill = 129,
            tkill = 130,
            tgkill = 131,
            sigaltstack = 132,
            rt_sigsuspend = 133,
            rt_sigaction = 134,
            rt_sigprocmask = 135,
            rt_sigpending = 136,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            rt_sigtimedwait = 137,
#endif
            rt_sigqueueinfo = 138,
            rt_sigreturn = 139,
            setpriority = 140, // kernel/sys.c 
            getpriority = 141,
            reboot = 142,
            setregid = 143,
            setgid = 144,
            setreuid = 145,
            setuid = 146,
            setresuid = 147,
            getresuid = 148,
            setresgid = 149,
            getresgid = 150,
            setfsuid = 151,
            setfsgid = 152,
            times = 153,
            setpgid = 154,
            getpgid = 155,
            getsid = 156,
            setsid = 157,
            getgroups = 158,
            setgroups = 159,
            uname = 160,
            sethostname = 161,
            setdomainname = 162,
#ifdef __ARCH_WANT_SET_GET_RLIMIT
            getrlimit = 163, // getrlimit and setrlimit are superseded with prlimit64
            setrlimit = 164,
#endif
            getrusage = 165,
            umask = 166,
            prctl = 167,
            getcpu = 168,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            gettimeofday = 169, // kernel/time.c 
            settimeofday = 170,
            adjtimex = 171,
#endif
            getpid = 172, // kernel/timer.c 
            getppid = 173,
            getuid = 174,
            geteuid = 175,
            getgid = 176,
            getegid = 177,
            gettid = 178,
            sysinfo = 179,
            mq_open = 180, // ipc/mqueue.c 
            mq_unlink = 181,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            mq_timedsend = 182,
            mq_timedreceive = 183,
#endif
            mq_notify = 184,
            mq_getsetattr = 185,
            msgget = 186, // ipc/msg.c 
            msgctl = 187,
            msgrcv = 188,
            msgsnd = 189,
            semget = 190, // ipc/sem.c 
            semctl = 191,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            semtimedop = 192,
#endif
            semop = 193,
            shmget = 194, // ipc/shm.c 
            shmctl = 195,
            shmat = 196,
            shmdt = 197,
            socket = 198, // net/socket.c 
            socketpair = 199,
            bind = 200,
            listen = 201,
            accept = 202,
            connect = 203,
            getsockname = 204,
            getpeername = 205,
            sendto = 206,
            recvfrom = 207,
            setsockopt = 208,
            getsockopt = 209,
            shutdown = 210,
            sendmsg = 211,
            recvmsg = 212,
            readahead = 213, // mm/filemap.c
            brk = 214, // mm/nommu.c, also with MMU 
            munmap = 215,
            mremap = 216,
            add_key = 217, // security/keys/keyctl.c 
            request_key = 218,
            keyctl = 219,
            clone = 220, // arch/example/kernel/sys_example.c 
            execve = 221,
            mmap = 222,
            fadvise64 = 223, // mm/fadvise.c
#ifndef __ARCH_NOMMU
            swapon = 224, // mm/, CONFIG_MMU only 
            swapoff = 225,
            mprotect = 226,
            msync = 227,
            mlock = 228,
            munlock = 229,
            mlockall = 230,
            munlockall = 231,
            mincore = 232,
            madvise = 233,
            remap_file_pages = 234,
            mbind = 235,
            get_mempolicy = 236,
            set_mempolicy = 237,
            migrate_pages = 238,
            move_pages = 239,
#endif
            rt_tgsigqueueinfo = 240,
            perf_event_open = 241,
            accept4 = 242,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            recvmmsg = 243,
#endif

// Architectures may provide up to 16 syscalls of their own starting with this value.

            arch_specific_syscall = 244,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            wait4 = 260,
#endif
            prlimit64 = 261,
            fanotify_init = 262,
            fanotify_mark = 263,
            name_to_handle_at = 264,
            open_by_handle_at = 265,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            clock_adjtime = 266,
#endif
            syncfs = 267,
            setns = 268,
            sendmmsg = 269,
            process_vm_readv = 270,
            process_vm_writev = 271,
            kcmp = 272,
            finit_module = 273,
            sched_setattr = 274,
            sched_getattr = 275,
            renameat2 = 276,
            seccomp = 277,
            getrandom = 278,
            memfd_create = 279,
            bpf = 280,
            execveat = 281,
            userfaultfd = 282,
            membarrier = 283,
            mlock2 = 284,
            copy_file_range = 285,
            preadv2 = 286,
            pwritev2 = 287,
            pkey_mprotect = 288,
            pkey_alloc = 289,
            pkey_free = 290,
            statx = 291,
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
            io_pgetevents = 292,
#endif
            rseq = 293,
            kexec_file_load = 294,

// 295 through 402 are unassigned to sync up with generic numbers, don't use

#if __BITS_PER_LONG == 32
            clock_gettime64 = 403,
            clock_settime64 = 404,
            clock_adjtime64 = 405,
            clock_getres_time64 = 406,
            clock_nanosleep_time64 = 407,
            timer_gettime64 = 408,
            timer_settime64 = 409,
            timerfd_gettime64 = 410,
            timerfd_settime64 = 411,
            utimensat_time64 = 412,
            pselect6_time64 = 413,
            ppoll_time64 = 414,
            io_pgetevents_time64 = 416,
            recvmmsg_time64 = 417,
            mq_timedsend_time64 = 418,
            mq_timedreceive_time64 = 419,
            semtimedop_time64 = 420,
            rt_sigtimedwait_time64 = 421,
            futex_time64 = 422,
            sched_rr_get_interval_time64 = 423,
#endif
            pidfd_send_signal = 424,
            io_uring_setup = 425,
            io_uring_enter = 426,
            io_uring_register = 427,
            open_tree = 428,
            move_mount = 429,
            fsopen = 430,
            fsconfig = 431,
            fsmount = 432,
            fspick = 433,
            pidfd_open = 434,
#ifdef __ARCH_WANT_SYS_CLONE3
            clone3 = 435,
#endif

            open = 1024,
            unlink = 1026,
            stat = 1038,
            chown = 1039,
        };
    }

    struct utsname {
        static constexpr usize UTSNAME_LENGTH = 65;

        char sysname[UTSNAME_LENGTH];       // Name of the implementation of the operating system.
        char nodename[UTSNAME_LENGTH];      // Name of this node on the network.
        char release[UTSNAME_LENGTH];       // Current release level of this implementation.
        char version[UTSNAME_LENGTH];       // Current version level of this release.
        char machine[UTSNAME_LENGTH];       // Name of the hardware type the system is running on.
        char domainname[UTSNAME_LENGTH];
    };

    struct stat {
        struct timespec {
            u32 tv_sec;
            u32 tv_nsec;
        };

        u32 st_dev;                 /* Device.  */
        u32 st_ino;                 /* File serial number. */
        u32 st_mode;                /* File mode.  */
        u32 st_nlink;               /* Link count.  */
        u32 st_uid;                 /* User ID of the file's owner. */
        u32 st_gid;                 /* Group ID of the file's group.*/
        u32 st_rdev;                /* Device number, if device.  */
        u32 __pad1;
        u32 st_size;                /* Size of file, in bytes. */
        u32 st_blksize;             /* Optimal block size for I/O.  */
        u32 __pad2;
        u32 st_blocks;              /* 512-byte blocks */
        timespec atime;
        timespec mtime;             /* Time of last modification.  */
        timespec ctime;             /* Time of last status change.  */
        u32 __glibc_reserved[2];

    };

    struct statx {
        struct statx_timestamp {
            u64 tv_sec;
            u32 tv_nsec;
            u32 __statx_timestamp_pad1[1];
        };

        u32 stx_mask;
        u32 stx_blksize;
        u64 stx_attributes;
        u32 stx_nlink;
        u32 stx_uid;
        u32 stx_gid;
        u16 stx_mode;
        u16 __statx_pad1[1];
        u16 stx_ino;
        u64 stx_size;
        u64 stx_blocks;
        u64 stx_attributes_mask;
        statx_timestamp stx_atime;
        statx_timestamp stx_btime;
        statx_timestamp stx_ctime;
        statx_timestamp stx_mtime;
        u32 stx_rdev_major;
        u32 stx_rdev_minor;
        u32 stx_dev_major;
        u32 stx_dev_minor;
        u64 __statx_pad2[14];
    };
}


#endif //NEUTRON_UNIX_STD_HPP
