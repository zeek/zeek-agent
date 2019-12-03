/* This is a generated file, see Makefile.am for its inputs. */
static const char evtype_strings[] = "TTY\0anomaly\0anomaly-response\0audit-daemon\0audit-rule\0av-decision\0configuration\0crypto\0dac-decision\0group-change\0"
	"integrity\0mac\0mac-decision\0system-services\0unknown\0user-account\0user-login\0user-space\0virt";
static const unsigned evtype_i2s_direct[] = {
	155,187,139,65,0,163,176,29,126,4,
	112,12,122,79,198,42,86,99,53,
};
static const char *evtype_i2s(int v) {
	return i2s_direct__(evtype_strings, evtype_i2s_direct, 0, 18, v);
}
