/* This is a generated file, see Makefile.am for its inputs. */
static const char sched_strings[] = "SCHED_BATCH\0SCHED_DEADLINE\0SCHED_FIFO\0SCHED_IDLE\0SCHED_OTHER\0SCHED_RR";
static const unsigned sched_i2s_direct[] = {
	49,27,61,0,-1u,38,12,
};
static const char *sched_i2s(int v) {
	return i2s_direct__(sched_strings, sched_i2s_direct, 0, 6, v);
}
