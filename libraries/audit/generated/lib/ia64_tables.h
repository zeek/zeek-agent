/* This is a generated file, see Makefile.am for its inputs. */
static const char ia64_syscall_strings[] = "_sysctl\0accept\0accept4\0access\0acct\0add_key\0adjtimex\0afs_syscall\0bdflush\0bind\0"
	"bpf\0brk\0capget\0capset\0chdir\0chmod\0chown\0chroot\0clock_adjtime\0clock_getres\0"
	"clock_gettime\0clock_nanosleep\0clock_settime\0clone\0clone2\0close\0connect\0copy_file_range\0creat\0delete_module\0"
	"dup\0dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0"
	"execve\0execveat\0exit\0exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0"
	"fchmod\0fchmodat\0fchown\0fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0"
	"fremovexattr\0fsetxattr\0fstat\0fstatfs\0fstatfs64\0fsync\0ftruncate\0futex\0futimesat\0get_mempolicy\0"
	"get_robust_list\0getcpu\0getcwd\0getdents\0getdents64\0getegid\0geteuid\0getgid\0getgroups\0getitimer\0"
	"getpeername\0getpgid\0getpid\0getpmsg\0getppid\0getpriority\0getrandom\0getresgid\0getresuid\0getrlimit\0"
	"getrusage\0getsid\0getsockname\0getsockopt\0gettid\0gettimeofday\0getuid\0getunwind\0getxattr\0init_module\0"
	"inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0ioctl\0"
	"ioprio_get\0ioprio_set\0kcmp\0kexec_load\0keyctl\0kill\0lchown\0lgetxattr\0link\0linkat\0"
	"listen\0listxattr\0llistxattr\0lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0lstat\0madvise\0mbind\0"
	"membarrier\0memfd_create\0migrate_pages\0mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlock2\0"
	"mlockall\0mmap\0mmap2\0mount\0mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0"
	"mq_unlink\0mremap\0msgctl\0msgget\0msgrcv\0msgsnd\0msync\0munlock\0munlockall\0munmap\0"
	"name_to_handle_at\0nanosleep\0newfstatat\0nfsservctl\0ni_syscall\0open\0open_by_handle_at\0openat\0pciconfig_read\0pciconfig_write\0"
	"perfmonctl\0personality\0pipe\0pipe2\0pivot_root\0poll\0ppoll\0prctl\0pread64\0preadv\0"
	"preadv2\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect\0ptrace\0putpmsg\0pwrite64\0pwritev\0pwritev2\0"
	"quotactl\0read\0readahead\0readlink\0readlinkat\0readv\0reboot\0recv\0recvfrom\0recvmmsg\0"
	"recvmsg\0remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0request_key\0restart_syscall\0rmdir\0rt_sigaction\0"
	"rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0sched_get_priority_max\0sched_get_priority_min\0sched_getaffinity\0"
	"sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0select\0"
	"semctl\0semget\0semop\0semtimedop\0send\0sendfile\0sendmmsg\0sendmsg\0sendto\0set_mempolicy\0"
	"set_robust_list\0set_tid_address\0set_zone_reclaim\0setdomainname\0setfsgid\0setfsuid\0setgid\0setgroups\0sethostname\0setitimer\0"
	"setns\0setpgid\0setpriority\0setregid\0setresgid\0setresuid\0setreuid\0setrlimit\0setsid\0setsockopt\0"
	"settimeofday\0setuid\0setxattr\0shmat\0shmctl\0shmdt\0shmget\0shutdown\0sigaltstack\0signalfd\0"
	"signalfd4\0socket\0socketpair\0splice\0stat\0statfs\0statfs64\0swapoff\0swapon\0symlink\0"
	"symlinkat\0sync\0sync_file_range\0syncfs\0sysfs\0sysinfo\0syslog\0tee\0tgkill\0timer_create\0"
	"timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_create\0timerfd_gettime\0timerfd_settime\0times\0tkill\0"
	"truncate\0tux\0umask\0umount\0uname\0unlink\0unlinkat\0unshare\0uselib\0userfaultfd\0"
	"ustat\0utimensat\0utimes\0vhangup\0vmsplice\0vserver\0wait4\0waitid\0write\0writev";
static const unsigned ia64_syscall_s2i_s[] = {
	0,8,15,23,30,35,43,52,64,72,
	77,81,85,92,99,105,111,117,124,138,
	151,165,181,195,201,208,214,222,238,244,
	258,262,267,272,285,299,309,321,332,340,
	349,356,365,370,381,391,401,411,425,439,
	446,453,462,469,478,484,494,504,517,528,
	534,547,557,563,571,581,587,597,603,613,
	627,643,650,657,666,677,685,693,700,710,
	720,732,740,747,755,763,775,785,795,805,
	815,825,832,844,855,862,875,882,892,901,
	913,931,944,958,975,985,996,1009,1018,1028,
	1034,1045,1056,1061,1072,1079,1084,1091,1101,1106,
	1113,1120,1130,1141,1156,1169,1175,1185,1191,1199,
	1205,1216,1229,1243,1251,1257,1265,1271,1279,1285,
	1292,1301,1306,1312,1318,1327,1341,1351,1359,1375,
	1388,1398,1405,1412,1419,1426,1433,1439,1447,1458,
	1465,1483,1493,1504,1515,1526,1531,1549,1556,1571,
	1587,1598,1610,1615,1621,1632,1637,1643,1649,1657,
	1664,1672,1682,1699,1717,1725,1732,1740,1749,1757,
	1766,1775,1780,1790,1799,1810,1816,1823,1828,1837,
	1846,1854,1871,1883,1890,1899,1909,1921,1937,1943,
	1956,1970,1985,2001,2014,2028,2044,2062,2085,2108,
	2126,2140,2155,2174,2196,2214,2228,2243,2262,2274,
	2281,2288,2295,2301,2312,2317,2326,2335,2343,2350,
	2364,2380,2396,2413,2427,2436,2445,2452,2462,2474,
	2484,2490,2498,2510,2519,2529,2539,2548,2558,2565,
	2576,2589,2596,2605,2611,2618,2624,2631,2640,2652,
	2661,2671,2678,2689,2696,2701,2708,2717,2725,2732,
	2740,2750,2755,2771,2778,2784,2792,2799,2803,2810,
	2823,2836,2853,2867,2881,2889,2904,2920,2936,2942,
	2948,2957,2961,2967,2974,2980,2987,2996,3004,3011,
	3023,3029,3039,3046,3054,3063,3071,3077,3084,3090,
};
static const int ia64_syscall_s2i_i[] = {
	1150,1194,1334,1049,1064,1271,1131,1141,1138,1191,
	1341,1060,1185,1186,1034,1038,1039,1068,1328,1255,
	1254,1256,1253,1128,1213,1029,1192,1347,1030,1134,
	1057,1070,1316,1243,1315,1244,1305,1245,1309,1314,
	1033,1342,1025,1236,1293,1234,1303,1323,1324,1035,
	1099,1292,1100,1284,1066,1052,1222,1335,1225,1145,
	1228,1219,1212,1104,1257,1051,1098,1230,1285,1260,
	1299,1304,1184,1144,1214,1063,1047,1062,1077,1119,
	1196,1079,1041,1188,1042,1101,1339,1075,1073,1085,
	1086,1082,1195,1204,1105,1087,1046,1215,1220,1133,
	1278,1277,1318,1279,1242,1239,1240,1238,1241,1065,
	1275,1274,1345,1268,1273,1053,1124,1221,1031,1289,
	1193,1223,1224,1237,1227,1040,1218,1211,1209,1259,
	1344,1340,1280,1208,1055,1282,1037,1283,1153,1346,
	1154,1151,1172,1043,1155,1267,1266,1262,1265,1264,
	1263,1156,1112,1109,1111,1110,1157,1158,1159,1152,
	1326,1168,1286,1169,1024,1028,1327,1281,1173,1174,
	1175,1140,1058,1317,1207,1090,1295,1170,1148,1319,
	1348,1325,1332,1333,1294,1048,1189,1149,1320,1349,
	1137,1026,1216,1092,1291,1146,1096,1200,1201,1322,
	1206,1125,1226,1054,1288,1338,1272,1246,1056,1177,
	1178,1179,1180,1181,1182,1183,1321,1165,1166,1232,
	1337,1160,1162,1167,1231,1336,1161,1163,1164,1089,
	1108,1106,1107,1247,1198,1187,1331,1205,1199,1261,
	1298,1233,1276,1129,1143,1142,1061,1078,1083,1118,
	1330,1080,1102,1072,1076,1074,1071,1084,1081,1203,
	1088,1045,1217,1114,1116,1115,1113,1202,1176,1307,
	1313,1190,1197,1297,1210,1103,1258,1095,1094,1091,
	1290,1050,1300,1329,1139,1127,1117,1301,1235,1248,
	1252,1251,1250,1249,1308,1310,1312,1311,1059,1229,
	1097,1120,1067,1044,1130,1032,1287,1296,1093,1343,
	1069,1306,1036,1123,1302,1269,1126,1270,1027,1147,
};
static int ia64_syscall_s2i(const char *s, int *value) {
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
	return s2i__(ia64_syscall_strings, ia64_syscall_s2i_s, ia64_syscall_s2i_i, 320, copy, value);
	}
}
static const unsigned ia64_syscall_i2s_direct[] = {
	1515,365,1775,3084,1526,208,238,1101,2980,349,
	99,439,3039,1265,105,111,1169,740,755,1312,
	2967,2589,875,685,1725,23,2750,581,484,1079,
	1883,1251,1937,258,1610,2936,81,2445,693,677,
	30,1028,478,2961,117,3023,262,2539,2510,795,
	2529,785,2519,700,2452,732,2490,2558,825,2462,
	2548,805,815,862,2576,2274,1632,2732,1790,3004,
	2725,2717,1816,2948,587,446,462,763,2498,2701,
	563,855,2288,2295,2281,1412,1426,1419,1405,2624,
	2605,2618,2611,2792,2474,710,2957,-1u,-1u,3046,
	1084,1854,3071,2784,195,2413,2974,43,-1u,901,
	244,-1u,-1u,1766,64,2778,1598,52,2436,2427,
	657,528,1810,3090,1649,1740,0,1301,1458,1279,
	1292,1318,1398,1433,1439,1447,2140,2228,2155,2243,
	2262,2062,2085,2174,1483,1504,1643,-1u,1306,1556,
	1571,1587,2640,1943,1956,1970,1985,2001,2014,2028,
	650,85,92,2317,747,1732,2671,72,214,1113,
	8,832,720,2678,2312,2343,1823,1828,2631,2565,
	844,2335,1846,1621,1243,1191,2696,1185,557,201,
	666,882,1780,2596,1175,547,892,1091,494,1120,
	1130,517,1871,1156,534,2942,597,2196,2108,2380,
	391,2803,370,1141,1009,985,996,1018,975,272,
	299,321,1921,2301,2810,2867,2853,2836,2823,181,
	151,138,165,571,2708,1199,613,2350,1351,1388,
	1375,1359,1341,1327,1061,3063,3077,35,1909,1072,
	1045,1034,2396,931,913,958,1229,1549,1257,1271,
	469,603,1493,2987,1890,1106,2740,1799,453,381,
	1717,1637,2996,2689,2364,627,2755,2799,3054,401,
	643,309,3029,2652,2881,332,2889,2920,2904,2661,
	340,285,267,1615,944,1657,1749,2044,1837,411,
	425,1672,1465,1531,124,2771,2484,2326,1682,1699,
	15,504,2214,2126,1899,775,1216,77,356,3011,
	1205,1056,1285,222,1664,1757,
};
static const char *ia64_syscall_i2s(int v) {
	return i2s_direct__(ia64_syscall_strings, ia64_syscall_i2s_direct, 1024, 1349, v);
}
