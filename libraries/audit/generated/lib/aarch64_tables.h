/* This is a generated file, see Makefile.am for its inputs. */
static const char aarch64_syscall_strings[] = "accept\0accept4\0acct\0add_key\0adjtimex\0bind\0bpf\0brk\0capget\0capset\0"
	"chdir\0chroot\0clock_adjtime\0clock_getres\0clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0connect\0"
	"copy_file_range\0delete_module\0dup\0dup3\0epoll_create1\0epoll_ctl\0epoll_pwait\0eventfd2\0execve\0execveat\0"
	"exit\0exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0fchmod\0fchmodat\0"
	"fchown\0fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0fremovexattr\0fsetxattr\0"
	"fstatfs\0fsync\0ftruncate\0futex\0get_mempolicy\0get_robust_list\0getcpu\0getcwd\0getdents\0getegid\0"
	"geteuid\0getgid\0getgroups\0getitimer\0getpeername\0getpgid\0getpid\0getppid\0getpriority\0getrandom\0"
	"getresgid\0getresuid\0getrlimit\0getrusage\0getsid\0getsockname\0getsockopt\0gettid\0gettimeofday\0getuid\0"
	"getxattr\0init_module\0inotify_add_watch\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_pgetevents\0io_setup\0"
	"io_submit\0ioctl\0ioprio_get\0ioprio_set\0kcmp\0kexec_load\0keyctl\0kill\0lgetxattr\0linkat\0"
	"listen\0listxattr\0llistxattr\0lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0madvise\0mbind\0membarrier\0"
	"memfd_create\0migrate_pages\0mincore\0mkdirat\0mknodat\0mlock\0mlock2\0mlockall\0mmap\0mount\0"
	"move_pages\0mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0msgctl\0"
	"msgget\0msgrcv\0msgsnd\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstat\0"
	"newfstatat\0nfsservctl\0open_by_handle_at\0openat\0perf_event_open\0personality\0pipe2\0pivot_root\0pkey_alloc\0pkey_free\0"
	"pkey_mprotect\0ppoll\0prctl\0pread\0preadv\0preadv2\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect6\0"
	"ptrace\0pwrite\0pwritev\0pwritev2\0quotactl\0read\0readahead\0readlinkat\0readv\0reboot\0"
	"recvfrom\0recvmmsg\0recvmsg\0remap_file_pages\0removexattr\0renameat\0renameat2\0request_key\0restart_syscall\0rt_sigaction\0"
	"rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0sched_get_priority_max\0sched_get_priority_min\0sched_getaffinity\0"
	"sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0seccomp\0"
	"semctl\0semget\0semop\0semtimedop\0sendfile\0sendmmsg\0sendmsg\0sendto\0set_mempolicy\0set_robust_list\0"
	"set_tid_address\0setdomainname\0setfsgid\0setfsuid\0setgid\0setgroups\0sethostname\0setitimer\0setns\0setpgid\0"
	"setpriority\0setregid\0setresgid\0setresuid\0setreuid\0setrlimit\0setsid\0setsockopt\0settimeofday\0setuid\0"
	"setxattr\0shmat\0shmctl\0shmdt\0shmget\0shutdown\0sigaltstack\0signalfd4\0socket\0socketpair\0"
	"splice\0statfs\0statx\0swapoff\0swapon\0symlinkat\0sync\0sync_file_range\0syncfs\0sysinfo\0"
	"syslog\0tee\0tgkill\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd_create\0timerfd_gettime\0"
	"timerfd_settime\0times\0tkill\0truncate\0umask\0umount2\0uname\0unlinkat\0unshare\0userfaultfd\0"
	"utimensat\0vhangup\0vmsplice\0wait4\0waitid\0write\0writev";
static const unsigned aarch64_syscall_s2i_s[] = {
	0,7,15,20,28,37,42,46,50,57,
	64,70,77,91,104,118,134,148,154,160,
	168,184,198,202,207,221,231,243,252,259,
	268,273,284,294,304,314,328,342,349,356,
	365,372,381,387,397,407,420,431,437,450,
	460,468,474,484,490,504,520,527,534,543,
	551,559,566,576,586,598,606,613,621,633,
	643,653,663,673,683,690,702,713,720,733,
	740,749,761,779,793,810,820,831,844,858,
	867,877,883,894,905,910,921,928,933,943,
	950,957,967,978,993,1006,1012,1022,1030,1036,
	1047,1060,1074,1082,1090,1098,1104,1111,1120,1125,
	1131,1142,1151,1165,1175,1183,1199,1212,1222,1229,
	1236,1243,1250,1257,1263,1271,1282,1289,1307,1317,
	1326,1337,1348,1366,1373,1389,1401,1407,1418,1429,
	1439,1453,1459,1465,1471,1478,1486,1496,1513,1531,
	1540,1547,1554,1562,1571,1580,1585,1595,1606,1612,
	1619,1628,1637,1645,1662,1674,1683,1693,1705,1721,
	1734,1748,1763,1779,1792,1806,1822,1840,1863,1886,
	1904,1918,1933,1952,1974,1992,2006,2021,2040,2052,
	2060,2067,2074,2080,2091,2100,2109,2117,2124,2138,
	2154,2170,2184,2193,2202,2209,2219,2231,2241,2247,
	2255,2267,2276,2286,2296,2305,2315,2322,2333,2346,
	2353,2362,2368,2375,2381,2388,2397,2409,2419,2426,
	2437,2444,2451,2457,2465,2472,2482,2487,2503,2510,
	2518,2525,2529,2536,2549,2562,2579,2593,2607,2622,
	2638,2654,2660,2666,2675,2681,2689,2695,2704,2712,
	2724,2734,2742,2751,2757,2764,2770,
};
static const int aarch64_syscall_s2i_i[] = {
	202,242,89,217,171,200,280,214,90,91,
	49,51,266,114,113,115,112,220,57,203,
	285,106,23,24,20,21,22,19,221,281,
	93,94,48,223,47,262,263,50,52,53,
	55,54,25,83,10,273,13,32,16,7,
	44,82,46,98,236,100,168,17,61,177,
	175,176,158,102,205,155,172,173,141,278,
	150,148,163,165,156,204,209,178,169,174,
	8,105,27,26,28,3,1,4,292,0,
	2,29,31,30,272,104,219,129,9,37,
	201,11,12,18,15,62,6,233,235,283,
	279,238,232,34,33,228,284,230,222,40,
	239,226,185,184,180,183,182,181,216,187,
	186,188,189,227,229,231,215,264,101,80,
	79,42,265,56,241,92,59,41,289,290,
	288,73,167,67,69,286,261,270,271,72,
	117,68,70,287,60,63,213,78,65,142,
	207,243,212,234,14,38,276,218,128,134,
	136,135,138,139,133,137,240,125,126,123,
	275,121,120,127,122,274,118,119,124,277,
	191,190,193,192,71,269,211,206,237,99,
	96,162,152,151,144,159,161,103,268,154,
	140,143,149,147,145,164,157,208,170,146,
	5,196,195,197,194,210,132,74,198,199,
	76,43,291,225,224,36,81,84,267,179,
	116,77,131,107,111,109,108,110,85,87,
	86,153,130,45,166,39,160,35,97,282,
	88,58,75,260,95,64,66,
};
static int aarch64_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	 if (s == NULL || value == NULL)
		return 0;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(aarch64_syscall_strings, aarch64_syscall_s2i_s, aarch64_syscall_s2i_i, 277, copy, value);
	}
}
static const unsigned aarch64_syscall_i2s_direct[] = {
	858,820,867,810,831,2353,1012,450,740,933,
	397,957,967,420,1662,993,437,527,978,243,
	207,221,231,198,202,381,779,761,793,877,
	894,883,431,1090,1082,2695,2472,943,1674,2681,
	1125,1407,1337,2444,460,2666,474,304,284,64,
	342,70,349,356,372,365,1366,154,2734,1401,
	1571,534,1006,1580,2764,1606,2770,1465,1547,1471,
	1554,2091,1531,1453,2409,2742,2437,2525,1595,1326,
	1317,2482,468,387,2487,2607,2638,2622,2724,15,
	50,57,1389,268,273,2757,2154,2704,484,2138,
	504,1307,576,2231,910,749,184,2536,2579,2562,
	2593,2549,134,104,91,118,2518,1540,2006,2021,
	1933,1918,1974,1886,2040,1840,1863,1952,1705,928,
	2660,2529,2397,1792,1721,1748,1734,1806,1763,1779,
	2255,621,1612,2267,2202,2296,2346,2286,653,2276,
	643,2193,2184,2654,2247,598,683,2315,566,2209,
	2689,2219,2170,663,2305,673,2675,1459,520,720,
	2333,28,606,613,733,551,559,543,713,2510,
	1175,1212,1199,1183,1165,1151,1236,1229,1243,1250,
	2067,2060,2080,2074,2381,2368,2362,2375,2419,2426,
	37,950,0,160,690,586,2117,1619,2322,702,
	2388,2109,1637,1585,46,1282,1222,20,1693,921,
	148,252,1120,294,2465,2457,1142,1257,1098,1263,
	1111,1271,1074,1022,1645,1030,490,2124,1060,1131,
	1822,1373,7,1628,-1u,-1u,-1u,-1u,-1u,-1u,
	-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,
	2751,1486,314,328,1289,1348,77,2503,2241,2100,
	1496,1513,905,407,1992,1904,1683,2052,633,1047,
	42,259,2712,1036,1104,168,1478,1562,1439,1418,
	1429,2451,844,
};
static const char *aarch64_syscall_i2s(int v) {
	return i2s_direct__(aarch64_syscall_strings, aarch64_syscall_i2s_direct, 0, 292, v);
}
