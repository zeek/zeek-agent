/* This is a generated file, see Makefile.am for its inputs. */
static const char person_strings[] = "PER_BSD\0PER_HPUX\0PER_IRIX32\0PER_IRIX64\0PER_IRIXN32\0PER_ISCR4\0PER_LINUX\0PER_LINUX32\0PER_LINUX32_3GB\0PER_LINUX_32BIT\0"
	"PER_OSF4\0PER_OSR5\0PER_RISCOS\0PER_SCOSVR3\0PER_SOLARIS\0PER_SUNOS\0PER_SVR3\0PER_SVR4\0PER_UW7\0PER_WYSEV386\0"
	"PER_XENIX";
static const int person_i2s_i[] = {
	0,6,8,12,15,16,8388608,67108869,67108870,67108873,
	67108874,67108875,67108877,68157441,68157454,83886082,83886084,83886087,100663299,117440515,
	134217736,
};
static const unsigned person_i2s_s[] = {
	61,0,71,133,115,8,99,51,168,17,
	39,28,156,187,196,178,204,217,124,144,
	83,
};
static const char *person_i2s(int v) {
	return i2s_bsearch__(person_strings, person_i2s_i, person_i2s_s, 21, v);
}
