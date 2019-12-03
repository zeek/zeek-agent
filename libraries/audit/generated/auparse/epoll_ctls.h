/* This is a generated file, see Makefile.am for its inputs. */
static const char epoll_ctl_strings[] = "EPOLL_CTL_ADD\0EPOLL_CTL_DEL\0EPOLL_CTL_MOD";
static const unsigned epoll_ctl_i2s_direct[] = {
	0,14,28,
};
static const char *epoll_ctl_i2s(int v) {
	return i2s_direct__(epoll_ctl_strings, epoll_ctl_i2s_direct, 1, 3, v);
}
