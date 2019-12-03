/* This is a generated file, see Makefile.am for its inputs. */
static const char sock_type_strings[] = "SOCK_DCCP\0SOCK_DGRAM\0SOCK_PACKET\0SOCK_RAW\0SOCK_RDM\0SOCK_SEQPACKET\0SOCK_STREAM";
static const unsigned sock_type_i2s_direct[] = {
	66,10,33,42,51,0,-1u,-1u,-1u,21,
};
static const char *sock_type_i2s(int v) {
	return i2s_direct__(sock_type_strings, sock_type_i2s_direct, 1, 10, v);
}
