/* This is a generated file, see Makefile.am for its inputs. */
static const char nfproto_strings[] = "arp\0bridge\0decnet\0inet\0ipv4\0ipv6\0netdev\0unspecified";
static const unsigned nfproto_i2s_direct[] = {
	40,18,23,0,-1u,33,-1u,4,-1u,-1u,
	28,-1u,11,
};
static const char *nfproto_i2s(int v) {
	return i2s_direct__(nfproto_strings, nfproto_i2s_direct, 0, 12, v);
}
