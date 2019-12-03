/* This is a generated file, see Makefile.am for its inputs. */
static const char rlimit_strings[] = "RLIMIT_AS\0RLIMIT_CORE\0RLIMIT_CPU\0RLIMIT_DATA\0RLIMIT_FSIZE\0RLIMIT_LOCKS\0RLIMIT_MEMLOCK\0RLIMIT_MSGQUEUE\0RLIMIT_NICE\0RLIMIT_NOFILE\0"
	"RLIMIT_NPROC\0RLIMIT_RSS\0RLIMIT_RTPRIO\0RLIMIT_RTTIME\0RLIMIT_SIGPENDING\0RLIMIT_STACK";
static const unsigned rlimit_i2s_direct[] = {
	22,45,33,198,10,141,128,114,71,0,
	58,180,86,102,152,166,
};
static const char *rlimit_i2s(int v) {
	return i2s_direct__(rlimit_strings, rlimit_i2s_direct, 0, 15, v);
}
