/* This is a generated file, see Makefile.am for its inputs. */
static const char sock_strings[] = "accept\0accept4\0bind\0connect\0getpeername\0getsockname\0getsockopt\0listen\0recv\0recvfrom\0"
	"recvmmsg\0recvmsg\0send\0sendmmsg\0sendmsg\0sendto\0setsockopt\0shutdown\0socket\0socketpair";
static const unsigned sock_i2s_direct[] = {
	150,15,20,63,0,40,28,157,101,70,
	123,75,141,130,52,115,93,7,84,106,
};
static const char *sock_i2s(int v) {
	return i2s_direct__(sock_strings, sock_i2s_direct, 1, 20, v);
}
