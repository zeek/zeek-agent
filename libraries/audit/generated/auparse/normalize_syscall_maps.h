/* This is a generated file, see Makefile.am for its inputs. */
static const char normalize_syscall_map_strings[] = "accept\0accept4\0access\0adjtimex\0bind\0brk\0chmod\0chown\0clock_settime\0connect\0"
	"creat\0delete_module\0execve\0execveat\0faccessat\0fallocate\0fchmod\0fchmodat\0fchown\0fchownat\0"
	"finit_module\0fremovexattr\0fsetxattr\0fstat\0fstatfs\0ftruncate\0futimesat\0init_module\0kill\0lchown\0"
	"lremovexattr\0lsetxattr\0lstat\0mkdir\0mkdirat\0mknod\0mknodat\0mmap\0mount\0newfstatat\0"
	"open\0openat\0readlink\0readlinkat\0recvfrom\0recvmsg\0removexattr\0rename\0renameat\0renameat2\0"
	"rmdir\0sched_setattr\0sched_setparam\0sched_setscheduler\0sendmsg\0sendto\0setdomainname\0setegid\0seteuid\0setfsgid\0"
	"setfsuid\0setgid\0sethostname\0setregid\0setresgid\0setresuid\0setreuid\0settimeofday\0setuid\0setxattr\0"
	"stat\0stat64\0statfs\0stime\0symlink\0symlinkat\0tgkill\0tkill\0truncate\0umount\0"
	"umount2\0unlink\0unlinkat\0utime\0utimensat\0utimes";
static const unsigned normalize_syscall_map_s2i_s[] = {
	0,7,15,22,31,36,40,46,52,66,
	74,80,94,101,110,120,130,137,146,153,
	162,175,188,198,204,212,222,232,244,249,
	256,269,279,285,291,299,305,313,318,324,
	335,340,347,356,367,376,384,396,403,412,
	422,428,442,457,476,484,491,505,513,521,
	530,539,546,558,567,577,587,596,609,616,
	625,630,637,644,650,658,668,675,681,690,
	697,705,712,721,727,737,
};
static const int normalize_syscall_map_s2i_i[] = {
	16,16,10,31,17,35,3,4,31,18,
	1,6,15,15,10,1,3,3,4,4,
	5,2,2,10,34,1,14,5,21,4,
	2,2,10,7,7,32,32,35,8,10,
	1,1,1,1,19,19,2,9,9,9,
	13,36,36,36,20,20,33,30,29,30,
	29,30,33,30,30,29,29,31,29,2,
	10,10,34,31,11,11,21,21,1,12,
	12,13,13,14,14,14,
};
static int normalize_syscall_map_s2i(const char *s, int *value) {
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
	return s2i__(normalize_syscall_map_strings, normalize_syscall_map_s2i_s, normalize_syscall_map_s2i_i, 86, copy, value);
	}
}
