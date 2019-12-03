/* This is a generated file, see Makefile.am for its inputs. */
static const char signal_strings[] = "IGPWR\0SIG0\0SIGABRT\0SIGALRM\0SIGBUS\0SIGCHLD\0SIGCONT\0SIGFPE\0SIGHUP\0SIGILL\0"
	"SIGINT\0SIGIO\0SIGKILL\0SIGPIPE\0SIGPROF\0SIGQUIT\0SIGSEGV\0SIGSTKFLT\0SIGSTOP\0SIGSYS\0"
	"SIGTERM\0SIGTRAP\0SIGTSTP\0SIGTTIN\0SIGTTOU\0SIGURG\0SIGUSR1\0SIGUSR2\0SIGVTALRM\0SIGWINCH\0"
	"SIGXCPU\0SIGXFSZ";
static const unsigned signal_i2s_direct[] = {
	6,57,71,108,64,157,11,27,50,84,
	196,116,204,92,19,149,124,34,42,134,
	165,173,181,189,231,239,212,100,222,78,
	0,142,
};
static const char *signal_i2s(int v) {
	return i2s_direct__(signal_strings, signal_i2s_direct, 0, 31, v);
}
