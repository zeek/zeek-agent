/* This is a generated file, see Makefile.am for its inputs. */
static const char field_strings[] = "a0\0a1\0a2\0a3\0arch\0auid\0devmajor\0devminor\0dir\0egid\0"
	"euid\0exe\0exit\0field_compare\0filetype\0fsgid\0fstype\0fsuid\0gid\0inode\0"
	"key\0loginuid\0msgtype\0obj_gid\0obj_lev_high\0obj_lev_low\0obj_role\0obj_type\0obj_uid\0obj_user\0"
	"path\0perm\0pers\0pid\0ppid\0saddr_fam\0sessionid\0sgid\0subj_clr\0subj_role\0"
	"subj_sen\0subj_type\0subj_user\0success\0suid\0uid";
static const unsigned field_s2i_s[] = {
	0,3,6,9,12,17,22,31,40,44,
	49,54,58,63,77,86,92,99,105,109,
	115,119,128,136,144,157,169,178,187,195,
	204,209,214,219,223,228,238,248,253,262,
	272,281,291,301,309,314,
};
static const int field_s2i_i[] = {
	200,201,202,203,11,9,100,101,107,6,
	2,112,103,111,108,8,26,4,5,102,
	210,9,12,110,23,22,20,21,109,19,
	105,106,10,0,18,113,25,7,17,14,
	16,15,13,104,3,1,
};
static int field_s2i(const char *s, int *value) {
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
	return s2i__(field_strings, field_s2i_s, field_s2i_i, 46, copy, value);
	}
}
static const int field_i2s_i[] = {
	0,1,2,3,4,5,6,7,8,9,
	10,11,12,13,14,15,16,17,18,19,
	20,21,22,23,25,26,100,101,102,103,
	104,105,106,107,108,109,110,111,112,113,
	200,201,202,203,210,
};
static const unsigned field_i2s_s[] = {
	219,314,49,309,99,105,44,248,86,17,
	214,12,128,291,262,281,272,253,223,195,
	169,178,157,144,238,92,22,31,109,58,
	301,204,209,40,77,187,136,63,54,228,
	0,3,6,9,115,
};
static const char *field_i2s(int v) {
	return i2s_bsearch__(field_strings, field_i2s_i, field_i2s_s, 45, v);
}
