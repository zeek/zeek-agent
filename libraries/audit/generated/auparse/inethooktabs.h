/* This is a generated file, see Makefile.am for its inputs. */
static const char inethook_strings[] = "BROUTING\0FORWARD\0INPUT\0OUTPUT\0POSTROUTING\0PREROUTING";
static const unsigned inethook_i2s_direct[] = {
	42,17,9,23,30,0,
};
static const char *inethook_i2s(int v) {
	return i2s_direct__(inethook_strings, inethook_i2s_direct, 0, 5, v);
}
