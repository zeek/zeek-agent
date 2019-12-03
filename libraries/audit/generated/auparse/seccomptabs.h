/* This is a generated file, see Makefile.am for its inputs. */
static const char seccomp_strings[] = "allow\0errno\0kill\0kill-process\0log\0trace\0trap";
static const int seccomp_i2s_i[] = {
	-2147483648,0,196608,327680,2146435072,2147221504,2147418112,
};
static const unsigned seccomp_i2s_s[] = {
	17,12,40,6,34,30,0,
};
static const char *seccomp_i2s(int v) {
	return i2s_bsearch__(seccomp_strings, seccomp_i2s_i, seccomp_i2s_s, 7, v);
}
