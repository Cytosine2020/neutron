#ifndef NEUTRON_LINUX_STD_HPP
#define NEUTRON_LINUX_STD_HPP


#include "neutron_utility.hpp"


#define neutron_syscall_0(func) \
    sub_type()->set_x(IntRegT::A0, func())

#define neutron_syscall_1(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0)))

#define neutron_syscall_2(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0), \
                                        sub_type()->get_x(IntRegT::A1)))

#define neutron_syscall_3(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0), \
                                        sub_type()->get_x(IntRegT::A1), \
                                        sub_type()->get_x(IntRegT::A2)))

#define neutron_syscall_4(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0), \
                                        sub_type()->get_x(IntRegT::A1), \
                                        sub_type()->get_x(IntRegT::A2), \
                                        sub_type()->get_x(IntRegT::A3)))

#define neutron_syscall_5(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0), \
                                        sub_type()->get_x(IntRegT::A1), \
                                        sub_type()->get_x(IntRegT::A2), \
                                        sub_type()->get_x(IntRegT::A3), \
                                        sub_type()->get_x(IntRegT::A4)))

#define neutron_syscall_6(func) \
    sub_type()->set_x(IntRegT::A0, func(sub_type()->get_x(IntRegT::A0), \
                                        sub_type()->get_x(IntRegT::A1), \
                                        sub_type()->get_x(IntRegT::A2), \
                                        sub_type()->get_x(IntRegT::A3), \
                                        sub_type()->get_x(IntRegT::A4), \
                                        sub_type()->get_x(IntRegT::A5)))

#define neutron_syscall(num, func) \
    neutron_syscall_##num(func)


#define __ARCH_WANT_NEW_STAT

namespace neutron {
enum class SyscallNum {
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

/// auxiliary vector related macros and struct

constexpr usize NEUTRON_AT_NULL = 0;            // end of vector
constexpr usize NEUTRON_AT_IGNORE = 1;          // entry should be ignored
constexpr usize NEUTRON_AT_EXECFD = 2;          // file descriptor of program
constexpr usize NEUTRON_AT_PHDR = 3;            // program headers for program
constexpr usize NEUTRON_AT_PHENT = 4;           // size of program header entry
constexpr usize NEUTRON_AT_PHNUM = 5;           // number of program headers
constexpr usize NEUTRON_AT_PAGESZ = 6;          // system page size
constexpr usize NEUTRON_AT_BASE = 7;            // base address of interpreter
constexpr usize NEUTRON_AT_FLAGS = 8;           // flags
constexpr usize NEUTRON_AT_ENTRY = 9;           // entry point of program
constexpr usize NEUTRON_AT_NOTELF = 10;         // program is not ELF
constexpr usize NEUTRON_AT_UID = 11;            // real uid
constexpr usize NEUTRON_AT_EUID = 12;           // effective uid
constexpr usize NEUTRON_AT_GID = 13;            // real gid
constexpr usize NEUTRON_AT_EGID = 14;           // effective gid
constexpr usize NEUTRON_AT_PLATFORM = 15;       // string identifying CPU for optimizations
constexpr usize NEUTRON_AT_HWCAP = 16;          // arch dependent hints at CPU capabilities
constexpr usize NEUTRON_AT_CLKTCK = 17;         // frequency at which times() increments
// AT_* values 18 through 22 are reserved
constexpr usize NEUTRON_AT_SECURE = 23;         // secure mode boolean
constexpr usize NEUTRON_AT_BASE_PLATFORM = 24;  // string identifying real platform
constexpr usize NEUTRON_AT_RANDOM = 25;         // address of 16 random bytes
constexpr usize NEUTRON_AT_HWCAP2 = 26;         // extension of AT_HWCAP

constexpr usize NEUTRON_AT_EXECFN = 31;         // filename of program
constexpr usize NEUTRON_AT_SYSINFO = 32;
constexpr usize NEUTRON_AT_SYSINFO_EHDR = 33;
constexpr usize NEUTRON_AT_EMPTY_PATH = 0x1000; // Allow empty relative pathname.

/// fstat related macro

constexpr usize NEUTRON_F_DUPFD = 0;            // Duplicate file descriptor.
constexpr usize NEUTRON_F_GETFD = 1;            // Get file descriptor flags.
constexpr usize NEUTRON_F_SETFD = 2;            // Set file descriptor flags.
constexpr usize NEUTRON_F_GETFL = 3;            // Get file status flags.
constexpr usize NEUTRON_F_SETFL = 4;            // Set file status flags.
constexpr usize NEUTRON_F_GETLK = 5;            // Get record locking info.
constexpr usize NEUTRON_F_SETLK = 6;            // Set record locking info (non-blocking).
constexpr usize NEUTRON_F_SETLKW = 7;           // Set record locking info (blocking).
constexpr usize NEUTRON_F_SETOWN = 8;
constexpr usize NEUTRON_F_GETOWN = 9;
constexpr usize NEUTRON_F_SETSIG = 10;          // Set number of signal to be sent.
constexpr usize NEUTRON_F_GETSIG = 11;          // Get number of signal to be sent.
constexpr usize NEUTRON_F_GETLK64 = 12;         // Get record locking info.
constexpr usize NEUTRON_F_SETLK64 = 13;         // Set record locking info (non-blocking).
constexpr usize NEUTRON_F_SETLKW64 = 14;        // Set record locking info (blocking).
constexpr usize NEUTRON_F_SETOWN_EX = 15;       // Get owner (thread receiving SIGIO).
constexpr usize NEUTRON_F_GETOWN_EX = 16;       // Set owner (thread receiving SIGIO).
constexpr usize NEUTRON_F_OFD_GETLK = 36;
constexpr usize NEUTRON_F_OFD_SETLK = 37;
constexpr usize NEUTRON_F_OFD_SETLKW = 38;
constexpr usize NEUTRON_F_SETLEASE = 1024;      // Set a lease.
constexpr usize NEUTRON_F_GETLEASE = 1025;      // Enquire what lease is active.
constexpr usize NEUTRON_F_NOTIFY = 1026;        // Request notifications on a directory.
constexpr usize NEUTRON_F_DUPFD_CLOEXEC = 1030; // Duplicate file descriptor with close-on-exit set.
constexpr usize NEUTRON_F_SETPIPE_SZ = 1031;    // Set pipe page size array.
constexpr usize NEUTRON_F_GETPIPE_SZ = 1032;    // Set pipe page size array.
constexpr usize NEUTRON_F_ADD_SEALS = 1033;     // Add seals to file.
constexpr usize NEUTRON_F_GET_SEALS = 1034;     // Get seals for file.
// Set / get write life time hints.  
constexpr usize NEUTRON_F_GET_RW_HINT = 1035;
constexpr usize NEUTRON_F_SET_RW_HINT = 1036;
constexpr usize NEUTRON_F_GET_FILE_RW_HINT = 1037;
constexpr usize NEUTRON_F_SET_FILE_RW_HINT = 1038;
// For F_[GET|SET]FD.
constexpr usize NEUTRON_FD_CLOEXEC = 1;         // Actually anything with low bit set goes

struct flock {
    i16 type;     // Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.
    i16 whence;   // Where `start' is relative to (like `lseek').
    i32 start;    // Offset where the lock begins.
    i32 len;      // Size of the locked area; zero means until EOF.
    i32 pid;      // Process holding the lock.
};

struct flock64 {
    i16 type;     // Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.
    i16 whence;   // Where `start' is relative to (like `lseek').
    i64 start;    // Offset where the lock begins.
    i64 len;      // Size of the locked area; zero means until EOF.
    i32 pid;      // Process holding the lock.
};

struct f_owner_ex {
    enum pid_type {
        OWNER_TID = 0,                // Kernel thread.
        OWNER_PID,                    // Process.
        OWNER_PGRP,                   // Process group.
        OWNER_GID = OWNER_PGRP        // Alternative, obsolete name.
    };

    pid_type type;
    i32 pid;
};


/// open, pipe2 related macro

constexpr usize NEUTRON_O_WRONLY = 01;
constexpr usize NEUTRON_O_RDWR = 02;
constexpr usize NEUTRON_O_CREAT = 0100;                                 // Not fcntl.
constexpr usize NEUTRON_O_EXCL = 0200;                                  // Not fcntl.
constexpr usize NEUTRON_O_NOCTTY = 0400;                                // Not fcntl.
constexpr usize NEUTRON_O_TRUNC = 01000;                                // Not fcntl.
constexpr usize NEUTRON_O_APPEND = 02000;
constexpr usize NEUTRON_O_NONBLOCK = 04000;
constexpr usize NEUTRON_O_DSYNC = 010000;                               // Synchronize data.
constexpr usize NEUTRON_O_ASYNC = 020000;
constexpr usize NEUTRON_O_DIRECT = 040000;                              // Direct disk access.
constexpr usize NEUTRON_O_LARGEFILE = 0100000;
constexpr usize NEUTRON_O_DIRECTORY = 0200000;                          // Must be a directory.
constexpr usize NEUTRON_O_NOFOLLOW = 0400000;                           // Do not follow links.
constexpr usize NEUTRON_O_NOATIME = 01000000;                           // Do not set atime.
constexpr usize NEUTRON_O_CLOEXEC = 02000000;                           // Set close_on_exec.
constexpr usize NEUTRON_O_SYNC = 04010000;
// Resolve pathname but do not open file.
constexpr usize NEUTRON_O_PATH = 010000000;
// Atomically create nameless file.
constexpr usize NEUTRON_O_TMPFILE = 020000000 | NEUTRON_O_DIRECTORY;

/// lseek related macro

constexpr usize NEUTRON_SEEK_SET = 0;   // Seek from beginning of file.
constexpr usize NEUTRON_SEEK_CUR = 1;   // Seek from current position.
constexpr usize NEUTRON_SEEK_END = 2;   // Seek from end of file.
constexpr usize NEUTRON_SEEK_DATA = 3;  // Seek to next data.
constexpr usize NEUTRON_SEEK_HOLE = 4;  // Seek to next hole.

/// iovec

template<typename xlen>
struct iovec {
    typename xlen::UXLenT base;        // Starting address
    typename xlen::UXLenT len;         // Number of bytes to transfer
};

/// stat related struct

struct stat {
    struct timespec {
        u32 sec;
        u32 nsec;
    };

    u64 dev;                    // Device.
    u32 ino;                    // File serial number.
    u32 __pad1;
    u32 mode;                   // File mode.
    u32 nlink;                  // Link count.
    u32 uid;                    // User ID of the file's owner.
    u32 gid;                    // Group ID of the file's group.
    u64 rdev;                   // Device number, if device.
    u64 __pad2;
    u32 size;                   // Size of file, in bytes.
    u32 __pad3;
    u32 blksize;                // Optimal block size for I/O.
    u32 __pad4;
    u32 blocks;                 // 512-byte blocks
    u32 __pad5;
    timespec atime;
    timespec mtime;             // Time of last modification.
    timespec ctime;             // Time of last status change.
    u32 __reserved[2];
};

inline std::ostream &operator<<(std::ostream &stream, const stat::timespec &object) {
    stream << "struct statx::timestamp{<sec> " << object.sec
           << ", <nsec> " << object.nsec
           << '}';

    return stream;
}

inline std::ostream &operator<<(std::ostream &stream, const stat &object) {
    stream << "struct statx{<dev> " << object.dev
           << ", <ino> " << object.ino
           << ", <mode> " << object.mode
           << ", <nlink> " << object.nlink
           << ", <uid> " << object.uid
           << ", <gid> " << object.gid
           << ", <rdev> " << object.rdev
           << ", <size> " << object.size
           << ", <blksize> " << object.blksize
           << ", <blocks> " << object.blocks
           << ", <atime> " << object.atime
           << ", <mtime> " << object.mtime
           << ", <ctime> " << object.ctime
           << '}';

    return stream;
}

/// futex related macros

constexpr usize NEUTRON_FUTEX_WAIT = 0;
constexpr usize NEUTRON_FUTEX_WAKE = 1;
constexpr usize NEUTRON_FUTEX_FD = 2;
constexpr usize NEUTRON_FUTEX_REQUEUE = 3;
constexpr usize NEUTRON_FUTEX_CMP_REQUEUE = 4;
constexpr usize NEUTRON_FUTEX_WAKE_OP = 5;
constexpr usize NEUTRON_FUTEX_LOCK_PI = 6;
constexpr usize NEUTRON_FUTEX_UNLOCK_PI = 7;
constexpr usize NEUTRON_FUTEX_TRYLOCK_PI = 8;
constexpr usize NEUTRON_FUTEX_WAIT_BITSET = 9;
constexpr usize NEUTRON_FUTEX_WAKE_BITSET = 10;
constexpr usize NEUTRON_FUTEX_WAIT_REQUEUE_PI = 11;
constexpr usize NEUTRON_FUTEX_CMP_REQUEUE_PI = 12;

constexpr usize NEUTRON_FUTEX_PRIVATE_FLAG = 128;
constexpr usize NEUTRON_FUTEX_CLOCK_REALTIME = 256;
constexpr usize NEUTRON_FUTEX_CMD_MASK = ~(NEUTRON_FUTEX_PRIVATE_FLAG |
                                           NEUTRON_FUTEX_CLOCK_REALTIME);

constexpr usize NEUTRON_FUTEX_WAIT_PRIVATE = NEUTRON_FUTEX_WAIT | NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_WAKE_PRIVATE = NEUTRON_FUTEX_WAKE | NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_REQUEUE_PRIVATE = NEUTRON_FUTEX_REQUEUE |
                                                NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_CMP_REQUEUE_PRIVATE = NEUTRON_FUTEX_CMP_REQUEUE |
                                                    NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_WAKE_OP_PRIVATE = NEUTRON_FUTEX_WAKE_OP |
                                                NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_LOCK_PI_PRIVATE = NEUTRON_FUTEX_LOCK_PI |
                                                NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_UNLOCK_PI_PRIVATE = NEUTRON_FUTEX_UNLOCK_PI |
                                                  NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_TRYLOCK_PI_PRIVATE = NEUTRON_FUTEX_TRYLOCK_PI |
                                                   NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_WAIT_BITSET_PRIVATE = NEUTRON_FUTEX_WAIT_BITSET |
                                                    NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_WAKE_BITSET_PRIVATE = NEUTRON_FUTEX_WAKE_BITSET |
                                                    NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_WAIT_REQUEUE_PI_PRIVATE = NEUTRON_FUTEX_WAIT_REQUEUE_PI |
                                                        NEUTRON_FUTEX_PRIVATE_FLAG;
constexpr usize NEUTRON_FUTEX_CMP_REQUEUE_PI_PRIVATE = NEUTRON_FUTEX_CMP_REQUEUE_PI |
                                                       NEUTRON_FUTEX_PRIVATE_FLAG;

/// time related macros and struct

struct tms {
    u32 utime;
    u32 stime;
    u32 cutime;
    u32 cstime;
};

/// uname related macros and struct

struct utsname {
    static constexpr usize UTSNAME_LENGTH = 65;

    char sysname[UTSNAME_LENGTH];       // Name of the implementation of the operating system.
    char nodename[UTSNAME_LENGTH];      // Name of this node on the network.
    char release[UTSNAME_LENGTH];       // Current release level of this implementation.
    char version[UTSNAME_LENGTH];       // Current version level of this release.
    char machine[UTSNAME_LENGTH];       // Name of the hardware type the system is running on.
    char domainname[UTSNAME_LENGTH];
};

inline std::ostream &operator<<(std::ostream &stream, const utsname &object) {
    stream << "struct utsname{<sysname> \"" << object.sysname
           << "\", <nodename> \"" << object.nodename
           << "\", <release> \"" << object.release
           << "\", <version> \"" << object.version
           << "\", <machine> \"" << object.machine
           << "\"}";

    return stream;
}

/// sysinfo related macros and struct

struct sysinfo {
    i32 uptime;         // Seconds since boot
    u32 loads[3];       // 1, 5, and 15 minute load averages
    u32 totalram;       // Total usable main memory size
    u32 freeram;        // Available memory size
    u32 sharedram;      // Amount of shared memory
    u32 bufferram;      // Memory used by buffers
    u32 totalswap;      // Total swap space size
    u32 freeswap;       // Swap space still available
    u16 procs;          // Number of current processes
    u16 __pad1;
    u32 totalhigh;      // Total high memory size
    u32 freehigh;       // Available high memory size
    u32 mem_unit;       // Memory unit size in bytes
    char __pad2[20 - 4 * sizeof(u32)];
};

inline std::ostream &operator<<(std::ostream &stream, const sysinfo &object) {
    stream << "struct sysinfo{<uptime> " << object.uptime
           << ", <loads> " << object.loads
           << ", <totalram> " << object.totalram
           << ", <freeram> " << object.freeram
           << ", <sharedram> " << object.sharedram
           << ", <bufferram> " << object.bufferram
           << ", <totalswap> " << object.totalswap
           << ", <freeswap> " << object.freeswap
           << ", <procs> " << object.procs
           << ", <totalhigh> " << object.totalhigh
           << ", <freehigh> " << object.freehigh
           << ", <mem_unit> " << object.mem_unit
           << '}';

    return stream;
}

/// mmap related macros and struct

constexpr usize NEUTRON_PROT_READ = 0x1;            // Page can be read.
constexpr usize NEUTRON_PROT_WRITE = 0x2;           // Page can be written.
constexpr usize NEUTRON_PROT_EXEC = 0x4;            // Page can be executed.
constexpr usize NEUTRON_PROT_NONE = 0x0;            // Page can not be accessed.
// Extend change to start of growsdown vma (mprotect only).
constexpr usize NEUTRON_PROT_GROWSDOWN = 0x01000000;
// Extend change to start of growsup vma (mprotect only).
constexpr usize NEUTRON_PROT_GROWSUP = 0x02000000;

constexpr usize NEUTRON_MAP_FILE = 0;
constexpr usize NEUTRON_MAP_SHARED = 0x01;          // Share changes.
constexpr usize NEUTRON_MAP_PRIVATE = 0x02;         // Changes are private.
constexpr usize NEUTRON_MAP_SHARED_VALIDATE = 0x03; // Share changes and validate extension flags.
constexpr usize NEUTRON_MAP_TYPE = 0x0f;            // Mask for type of mapping.
constexpr usize NEUTRON_MAP_FIXED = 0x10;           // Interpret addr exactly.
constexpr usize NEUTRON_MAP_ANONYMOUS = 0x20;       // Don't use a file.
constexpr usize NEUTRON_MAP_GROWSDOWN = 0x00100;    // Stack-like segment.
constexpr usize NEUTRON_MAP_DENYWRITE = 0x00800;    // ETXTBSY.
constexpr usize NEUTRON_MAP_EXECUTABLE = 0x01000;   // Mark it as an executable.
constexpr usize NEUTRON_MAP_LOCKED = 0x02000;       // Lock the mapping.
constexpr usize NEUTRON_MAP_NORESERVE = 0x04000;    // Don't check for reservations.
constexpr usize NEUTRON_MAP_POPULATE = 0x08000;     // Populate (prefault) pagetables.
constexpr usize NEUTRON_MAP_NONBLOCK = 0x10000;     // Do not block on IO.
constexpr usize NEUTRON_MAP_STACK = 0x20000;        // Allocation is for a stack.
constexpr usize NEUTRON_MAP_HUGETLB = 0x40000;      // Create huge page mapping.
constexpr usize NEUTRON_MAP_SYNC = 0x80000;         // Perform synchronous page faults
constexpr usize NEUTRON_MAP_FIXED_NOREPLACE = 0x100000; // MAP_FIXED but do not unmap
// When MAP_HUGETLB is set bits [26:31] encode the log2 of the huge page size.
constexpr usize NEUTRON_MAP_HUGE_SHIFT = 26;
constexpr usize NEUTRON_MAP_HUGE_MASK = 0x3f;

/// statx related struct

struct statx {
    struct timestamp {
        u64 sec;
        u32 nsec;
        u32 __pad1[1];
    };

    u32 mask;
    u32 blksize;
    u64 attributes;
    u32 nlink;
    u32 uid;
    u32 gid;
    u16 mode;
    u16 __pad1[1];
    u64 ino;
    u64 size;
    u64 blocks;
    u64 attributes_mask;
    timestamp atime;
    timestamp btime;
    timestamp ctime;
    timestamp mtime;
    u32 rdev_major;
    u32 rdev_minor;
    u32 dev_major;
    u32 dev_minor;
    u64 __pad2[14];
};

inline std::ostream &operator<<(std::ostream &stream, const statx::timestamp &object) {
    stream << "struct statx::timestamp{<sec> " << object.sec
           << ", <nsec> " << object.nsec
           << '}';

    return stream;
}

inline std::ostream &operator<<(std::ostream &stream, const statx &object) {
    stream << "struct statx{<mask> " << object.mask
           << ", <blksize> " << object.blksize
           << ", <attributes> " << object.attributes
           << ", <nlink> " << object.nlink
           << ", <uid> " << object.uid
           << ", <gid> " << object.gid
           << ", <mode> " << object.mode
           << ", <ino> " << object.ino
           << ", <size> " << object.size
           << ", <blocks> " << object.blocks
           << ", <attributes_mask> " << object.attributes_mask
           << ", <atime> " << object.atime
           << ", <btime> " << object.btime
           << ", <ctime> " << object.ctime
           << ", <mtime> " << object.mtime
           << ", <rdev_major> " << object.rdev_major
           << ", <rdev_minor> " << object.rdev_minor
           << ", <dev_major> " << object.dev_major
           << ", <dev_minor> " << object.dev_minor
           << '}';

    return stream;
}

/// auxiliary entry

template<typename UXLenT>
struct AuxiliaryEntry {
    UXLenT type;
    UXLenT value;

    AuxiliaryEntry(UXLenT type, UXLenT value) : type{type}, value{value} {}
};

template<typename UXLenT>
using AuxiliaryT = std::vector<AuxiliaryEntry<UXLenT>>;

/// debug struct from dynamic loader

template<typename UXLenT>
struct DebugInfo {
    int version;
    UXLenT map;
    UXLenT brk;
    enum {
        CONSISTENT,
        ADD,
        DELETE
    } state;
    UXLenT ld_base;
};

template<typename UXLenT>
struct DebugMap {
    UXLenT addr;
    UXLenT name;
    UXLenT ld;
    UXLenT next;
    UXLenT prev;
};
}


#endif //NEUTRON_LINUX_STD_HPP
