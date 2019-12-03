/* This is a generated file, see Makefile.am for its inputs. */
static const char netaction_strings[] = "ACCEPT\0DROP\0REJECT";
static const unsigned netaction_i2s_direct[] = {
	0,7,12,
};
static const char *netaction_i2s(int v) {
	return i2s_direct__(netaction_strings, netaction_i2s_direct, 0, 2, v);
}
