/* This is a generated file, see Makefile.am for its inputs. */
static const char fam_strings[] = "alg\0appletalk\0ash\0atmpvc\0atmsvc\0ax25\0bluetooth\0bridge\0caif\0can\0"
	"decnet\0econet\0ieee802154\0inet\0inet6\0ipx\0irda\0isdn\0iucv\0kcm\0"
	"key\0llc\0local\0netbeui\0netlink\0netrom\0nfc\0packet\0phonet\0pppox\0"
	"qipcrtr\0rds\0rose\0rxrpc\0security\0smc\0sna\0tipc\0vsock\0wanpipe\0"
	"x25\0xdp";
static const unsigned fam_i2s_direct[] = {
	130,88,32,99,4,152,47,18,242,93,
	195,63,136,206,122,144,163,14,70,25,
	191,219,103,177,234,126,-1u,-1u,59,223,
	37,113,200,108,170,77,54,0,159,228,
	118,183,215,246,
};
static const char *fam_i2s(int v) {
	return i2s_direct__(fam_strings, fam_i2s_direct, 1, 44, v);
}
