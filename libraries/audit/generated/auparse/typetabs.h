/* This is a generated file, see Makefile.am for its inputs. */
static const char type_strings[] = "a0\0a1\0a2\0a3\0acct\0action\0addr\0arch\0auid\0cap_fi\0"
	"cap_fp\0cap_pa\0cap_pe\0cap_pi\0cap_pp\0capability\0cgroup\0cmd\0code\0comm\0"
	"cwd\0data\0device\0dir\0egid\0euid\0exe\0exit\0family\0fi\0"
	"file\0flags\0fp\0fsgid\0fsuid\0gid\0grp\0hook\0icmptype\0id\0"
	"igid\0img-ctx\0inode_gid\0inode_uid\0invalid_context\0ioctlcmd\0iuid\0key\0list\0macproto\0"
	"mode\0name\0new-chardev\0new-disk\0new-fs\0new-net\0new-rng\0new_gid\0new_group\0new_pe\0"
	"new_pi\0new_pp\0oauid\0obj\0obj_gid\0obj_uid\0ocomm\0oflag\0ogid\0old-auid\0"
	"old-chardev\0old-disk\0old-fs\0old-net\0old-rng\0old_pa\0old_pe\0old_pi\0old_pp\0old_prom\0"
	"ouid\0pa\0path\0pe\0per\0perm\0perm_mask\0pi\0pp\0proctitle\0"
	"prom\0proto\0res\0resp\0result\0root_dir\0saddr\0sauid\0scontext\0ses\0"
	"sgid\0sig\0sigev_signo\0subj\0suid\0sw\0syscall\0tcontext\0uid\0vm\0"
	"vm-ctx\0watch";
static const unsigned type_s2i_s[] = {
	0,3,6,9,12,17,24,29,34,39,
	46,53,60,67,74,81,92,99,103,108,
	113,117,122,129,133,138,143,147,152,159,
	162,167,173,176,182,188,192,196,201,210,
	213,218,226,236,246,262,271,276,280,285,
	294,299,304,316,325,332,340,348,356,366,
	373,380,387,393,397,405,413,419,425,430,
	439,451,460,467,475,483,490,497,504,511,
	520,525,528,533,536,540,545,555,558,561,
	571,576,582,586,591,598,607,613,619,628,
	632,637,641,653,658,663,666,674,683,687,
	690,697,
};
static const int type_s2i_i[] = {
	14,15,16,17,6,35,26,4,1,22,
	22,22,22,22,22,12,6,6,28,6,
	6,20,6,6,2,1,6,5,23,22,
	6,30,22,2,1,2,6,34,24,1,
	2,32,2,1,6,37,1,38,19,36,
	8,39,6,6,6,6,6,2,6,22,
	22,22,1,32,2,1,6,29,2,1,
	6,6,6,6,6,22,22,22,22,11,
	1,22,6,22,27,7,7,22,22,33,
	11,25,13,40,13,6,9,1,32,21,
	2,18,18,32,1,6,3,32,1,6,
	32,6,
};
static int type_s2i(const char *s, int *value) {
	return s2i__(type_strings, type_s2i_s, type_s2i_i, 112, s, value);
}
