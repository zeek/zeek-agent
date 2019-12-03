/* This is a generated file, see Makefile.am for its inputs. */
static const char clock_strings[] = "CLOCK_BOOTTIME\0CLOCK_BOOTTIME_ALARM\0CLOCK_MONOTONIC\0CLOCK_MONOTONIC_COARSE\0CLOCK_MONOTONIC_RAW\0CLOCK_PROCESS_CPUTIME_ID\0CLOCK_REALTIME\0CLOCK_REALTIME_ALARM\0CLOCK_REALTIME_COARSE\0CLOCK_SGI_CYCLE\0"
	"CLOCK_TAI\0CLOCK_THREAD_CPUTIME_ID";
static const unsigned clock_i2s_direct[] = {
	120,36,95,204,75,156,52,0,135,15,
	178,194,
};
static const char *clock_i2s(int v) {
	return i2s_direct__(clock_strings, clock_i2s_direct, 0, 11, v);
}
