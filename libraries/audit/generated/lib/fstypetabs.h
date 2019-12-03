/* This is a generated file, see Makefile.am for its inputs. */
static const char fstype_strings[] = "debugfs\0tracefs";
static const unsigned fstype_s2i_s[] = {
	0,8,
};
static const int fstype_s2i_i[] = {
	1684170528,1953653091,
};
static int fstype_s2i(const char *s, int *value) {
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
	return s2i__(fstype_strings, fstype_s2i_s, fstype_s2i_i, 2, copy, value);
	}
}
static const int fstype_i2s_i[] = {
	1684170528,1953653091,
};
static const unsigned fstype_i2s_s[] = {
	0,8,
};
static const char *fstype_i2s(int v) {
	return i2s_bsearch__(fstype_strings, fstype_i2s_i, fstype_i2s_s, 2, v);
}
