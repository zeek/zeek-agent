/* This is a generated file, see Makefile.am for its inputs. */
static const char seek_strings[] = "SEEK_CUR\0SEEK_DATA\0SEEK_END\0SEEK_HOLE\0SEEK_SET";
static const unsigned seek_i2s_direct[] = {
	38,0,19,9,28,
};
static const char *seek_i2s(int v) {
	return i2s_direct__(seek_strings, seek_i2s_direct, 0, 4, v);
}
