/* This is a generated file, see Makefile.am for its inputs. */
static const char icmptype_strings[] = "address-mask-reply\0address-mask-request\0destination-unreachable\0echo\0echo-reply\0info-reply\0info-request\0parameter-problem\0redirect\0source-quench\0"
	"time-exceeded\0timestamp-reply\0timestamp-request";
static const unsigned icmptype_i2s_direct[] = {
	69,-1u,-1u,40,131,122,-1u,-1u,64,-1u,
	-1u,145,104,175,159,91,80,19,0,
};
static const char *icmptype_i2s(int v) {
	return i2s_direct__(icmptype_strings, icmptype_i2s_direct, 0, 18, v);
}
