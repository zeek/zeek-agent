/* This is a generated file, see Makefile.am for its inputs. */
static const char machine_strings[] = "aarch64\0arm\0armeb\0armv5tejl\0armv5tel\0armv6l\0armv7l\0i386\0i486\0i586\0"
	"i686\0ppc\0ppc64\0ppc64le\0s390\0s390x\0x86_64";
static const unsigned machine_s2i_s[] = {
	0,8,12,18,28,37,44,51,56,61,
	66,71,75,81,89,94,100,
};
static const int machine_s2i_i[] = {
	9,8,8,8,8,8,8,0,0,0,
	0,4,3,10,6,5,1,
};
static int machine_s2i(const char *s, int *value) {
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
	return s2i__(machine_strings, machine_s2i_s, machine_s2i_i, 17, copy, value);
	}
}
static const unsigned machine_i2s_direct[] = {
	51,100,-1u,75,71,94,89,-1u,12,0,
	81,
};
static const char *machine_i2s(int v) {
	return i2s_direct__(machine_strings, machine_i2s_direct, 0, 10, v);
}
