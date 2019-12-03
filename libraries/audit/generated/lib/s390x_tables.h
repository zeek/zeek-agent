/* This is a generated file, see Makefile.am for its inputs. */
static const char s390x_syscall_strings[] = "_sysctl\0accept4\0access\0acct\0add_key\0adjtimex\0afs_syscall\0alarm\0bdflush\0bind\0"
	"bpf\0brk\0capget\0capset\0chdir\0chmod\0chown\0chroot\0clock_adjtime\0clock_getres\0"
	"clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0connect\0copy_file_range\0creat\0create_module\0delete_module\0"
	"dup\0dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0"
	"execve\0execveat\0exit\0exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0"
	"fchmod\0fchmodat\0fchown\0fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0"
	"fork\0fremovexattr\0fsetxattr\0fstat\0fstatfs\0fstatfs64\0fsync\0ftruncate\0futex\0futimesat\0"
	"get_kernel_syms\0get_robust_list\0getcpu\0getcwd\0getdents\0getegid\0geteuid\0getgid\0getgroups\0getitimer\0"
	"getpeername\0getpgid\0getpgrp\0getpid\0getpmsg\0getppid\0getpriority\0getrandom\0getresgid\0getresuid\0"
	"getrlimit\0getrusage\0getsid\0getsockname\0getsockopt\0gettid\0gettimeofday\0getuid\0getxattr\0idle\0"
	"init_module\0inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0"
	"ioctl\0ioprio_get\0ioprio_set\0ipc\0kcmp\0kexec_file_load\0kexec_load\0keyctl\0kill\0lchown\0"
	"lgetxattr\0link\0linkat\0listen\0listxattr\0llistxattr\0lremovexattr\0lseek\0lsetxattr\0lstat\0"
	"madvise\0membarrier\0memfd_create\0mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlock2\0"
	"mlockall\0mmap\0mount\0mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0"
	"mremap\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstatat\0nfsservctl\0nice\0"
	"open\0open_by_handle_at\0openat\0pause\0perf_event_open\0personality\0pipe\0pipe2\0pivot_root\0poll\0"
	"ppoll\0prctl\0pread\0preadv\0preadv2\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect6\0ptrace\0"
	"putpmsg\0pwrite\0pwritev\0pwritev2\0query_module\0quotactl\0read\0readahead\0readdir\0readlink\0"
	"readlinkat\0readv\0reboot\0recvfrom\0recvmmsg\0recvmsg\0remap_file_pages\0removexattr\0rename\0renameat\0"
	"renameat2\0request_key\0rmdir\0rt_sigaction\0rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0"
	"rt_tgsigqueueinfo\0s390_pci_mmio_read\0s390_pci_mmio_write\0s390_runtime_instr\0s390_sthyi\0sched_get_priority_max\0sched_get_priority_min\0sched_getaffinity\0sched_getattr\0sched_getparam\0"
	"sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0seccomp\0select\0sendfile\0"
	"sendmmsg\0sendmsg\0sendto\0set_robust_list\0set_tid_address\0setdomainname\0setfsgid\0setfsuid\0setgid\0setgroups\0"
	"sethostname\0setitimer\0setns\0setpgid\0setpriority\0setregid\0setresgid\0setresuid\0setreuid\0setrlimit\0"
	"setsid\0setsockopt\0settimeofday\0setuid\0setxattr\0shutdown\0sigaction\0sigaltstack\0signal\0signalfd\0"
	"signalfd4\0sigpending\0sigprocmask\0sigreturn\0sigsuspend\0socket\0socketcall\0socketpair\0splice\0stat\0"
	"statfs\0statfs64\0statx\0swapoff\0swapon\0symlink\0symlinkat\0sync\0sync_file_range\0syncfs\0"
	"sysfs\0sysinfo\0syslog\0tee\0tgkill\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0"
	"timerfd\0timerfd_create\0timerfd_gettime\0timerfd_settime\0times\0tkill\0truncate\0umask\0umount\0umount2\0"
	"uname\0unlink\0unlinkat\0unshare\0uselib\0userfaultfd\0ustat\0utime\0utimensat\0utimes\0"
	"vfork\0vhangup\0vmsplice\0wait4\0waitid\0write\0writev";
static const unsigned s390x_syscall_s2i_s[] = {
	0,8,16,23,28,36,45,57,63,71,
	76,80,84,91,98,104,110,116,123,137,
	150,164,180,194,200,206,214,230,236,250,
	264,268,273,278,291,305,315,327,338,346,
	355,362,371,376,387,397,407,417,431,445,
	452,459,468,475,484,490,500,510,523,534,
	540,545,558,568,574,582,592,598,608,614,
	624,640,656,663,670,679,687,695,702,712,
	722,734,742,750,757,765,773,785,795,805,
	815,825,835,842,854,865,872,885,892,901,
	906,918,936,949,963,980,990,1001,1014,1023,
	1033,1039,1050,1061,1065,1070,1086,1097,1104,1109,
	1116,1126,1131,1138,1145,1155,1166,1179,1185,1195,
	1201,1209,1220,1233,1241,1247,1255,1261,1269,1275,
	1282,1291,1296,1302,1311,1325,1335,1343,1359,1372,
	1382,1389,1395,1403,1414,1421,1439,1449,1460,1471,
	1476,1481,1499,1506,1512,1528,1540,1545,1551,1562,
	1567,1573,1579,1585,1592,1600,1610,1627,1645,1654,
	1661,1669,1676,1684,1693,1706,1715,1720,1730,1738,
	1747,1758,1764,1771,1780,1789,1797,1814,1826,1833,
	1842,1852,1864,1870,1883,1897,1912,1928,1941,1955,
	1971,1989,2008,2028,2047,2058,2081,2104,2122,2136,
	2151,2170,2192,2210,2224,2239,2258,2270,2278,2285,
	2294,2303,2311,2318,2334,2350,2364,2373,2382,2389,
	2399,2411,2421,2427,2435,2447,2456,2466,2476,2485,
	2495,2502,2513,2526,2533,2542,2551,2561,2573,2580,
	2589,2599,2610,2622,2632,2643,2650,2661,2672,2679,
	2684,2691,2700,2706,2714,2721,2729,2739,2744,2760,
	2767,2773,2781,2788,2792,2799,2812,2825,2842,2856,
	2870,2878,2893,2909,2925,2931,2937,2946,2952,2959,
	2967,2973,2980,2989,2997,3004,3016,3022,3028,3038,
	3045,3051,3059,3068,3074,3081,3087,
};
static const int s390x_syscall_s2i_i[] = {
	149,364,33,51,278,124,137,27,134,361,
	351,45,184,185,12,15,212,61,337,261,
	260,262,259,120,6,362,375,8,127,129,
	41,63,326,249,327,250,312,251,318,323,
	11,354,1,248,300,253,314,332,333,133,
	94,299,207,291,55,148,229,344,232,143,
	2,235,226,108,100,266,118,93,238,292,
	130,305,311,183,141,202,201,200,205,105,
	368,132,65,20,188,64,96,349,211,209,
	191,77,147,367,365,236,78,199,227,112,
	128,285,284,324,286,247,244,245,243,246,
	54,283,282,117,343,381,277,280,37,198,
	228,9,296,363,230,231,234,19,225,107,
	219,356,350,218,39,289,14,290,150,374,
	152,90,21,125,276,275,271,274,273,272,
	163,144,151,153,91,335,162,293,169,34,
	5,336,288,29,331,136,42,325,217,168,
	302,172,180,328,376,334,340,341,301,26,
	189,181,329,377,167,131,3,222,89,85,
	298,145,88,371,357,372,267,233,38,295,
	347,279,40,174,176,175,178,173,179,177,
	330,353,352,342,380,159,160,240,346,155,
	157,161,239,345,154,156,158,348,142,187,
	358,370,369,304,252,121,216,215,214,206,
	74,104,339,57,97,204,210,208,203,75,
	66,366,79,213,224,373,67,186,48,316,
	322,73,126,119,72,359,102,360,306,106,
	99,265,379,115,87,83,297,36,307,338,
	135,116,103,308,241,254,258,257,256,255,
	317,319,321,320,43,237,92,60,22,52,
	122,10,294,303,86,355,62,30,315,313,
	190,111,309,114,281,4,146,
};
static int s390x_syscall_s2i(const char *s, int *value) {
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
	return s2i__(s390x_syscall_strings, s390x_syscall_s2i_s, s390x_syscall_s2i_i, 317, copy, value);
	}
}
static const unsigned s390x_syscall_i2s_direct[] = {
	371,540,1715,3081,1476,200,-1u,230,1126,2973,
	355,98,-1u,1255,104,-1u,-1u,-1u,1179,750,
	1296,2952,-1u,-1u,-1u,1654,57,-1u,1506,3022,
	-1u,-1u,16,1471,-1u,2739,1104,1826,1241,1864,
	264,1540,2925,-1u,80,-1u,-1u,2573,-1u,-1u,
	23,2959,-1u,1033,484,-1u,2427,-1u,-1u,2946,
	116,3016,268,765,742,2495,2551,-1u,-1u,-1u,
	-1u,2632,2599,2399,2485,-1u,825,872,2513,-1u,
	-1u,-1u,2721,-1u,1738,2997,2714,1764,1730,1291,
	1414,2937,598,452,-1u,773,2435,-1u,2684,574,
	-1u,2650,2781,2411,712,2679,1195,568,-1u,-1u,
	3051,901,-1u,3068,2706,2773,1061,592,2622,194,
	2350,2967,-1u,36,1302,2610,236,906,250,624,
	1706,734,445,63,2767,1528,45,-1u,-1u,-1u,
	670,2278,534,1389,1758,3087,835,490,0,1269,
	1395,1282,1403,2224,2136,2239,2151,2258,2058,2081,
	2170,1439,1382,-1u,-1u,-1u,1693,1562,1460,-1u,
	-1u,1573,1928,1870,1897,1883,1955,1912,1941,1579,
	1669,-1u,663,84,91,2561,2285,757,1661,3045,
	815,-1u,-1u,-1u,-1u,-1u,-1u,1109,885,695,
	687,679,2476,2447,702,2389,468,2466,805,2456,
	795,110,2526,2382,2373,2364,1551,1233,1201,-1u,
	-1u,1720,-1u,2533,1185,558,892,1116,500,1145,
	1155,523,1814,1166,545,865,2931,608,2192,2104,
	2792,-1u,1014,990,1001,1023,980,376,278,305,
	327,2334,397,2799,2856,2842,2825,2812,180,150,
	137,164,-1u,-1u,2691,582,1797,-1u,-1u,-1u,
	1335,1372,1359,1343,1325,1311,1086,28,1852,1097,
	3074,1050,1039,936,918,963,-1u,1499,1247,1261,
	475,614,1449,2980,1833,1131,2729,1747,459,387,
	1645,1567,2989,2318,640,2672,2744,2788,3059,-1u,
	656,315,3038,407,3028,2580,2870,338,2878,2909,
	2893,2589,346,949,1545,273,291,1585,1676,1971,
	1512,417,431,1600,1421,1481,123,2760,2421,1610,
	1627,2028,1065,510,2210,2122,1842,2270,785,1220,
	76,2008,1989,362,3004,1209,1780,2294,2643,2661,
	71,206,1138,8,854,2502,842,722,2311,2303,
	1771,1789,2542,1275,214,1592,1684,-1u,2700,2047,
	1070,
};
static const char *s390x_syscall_i2s(int v) {
	return i2s_direct__(s390x_syscall_strings, s390x_syscall_i2s_direct, 1, 381, v);
}
