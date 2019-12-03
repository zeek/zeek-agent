/* This is a generated file, see Makefile.am for its inputs. */
static const char normalize_obj_kind_map_strings[] = "account\0admin-defined-rule\0audit-config\0block-device\0character-device\0device\0directory\0fifo\0file\0file-system\0"
	"firewall\0keystrokes\0mac-config\0memory\0printer\0process\0service\0socket\0software\0symlink\0"
	"system\0unknown\0user-session\0virtual-machine";
static const unsigned normalize_obj_kind_map_i2s_direct[] = {
	202,87,53,77,40,92,187,171,155,109,
	163,0,210,223,147,195,8,27,129,97,
	140,118,70,178,
};
static const char *normalize_obj_kind_map_i2s(int v) {
	return i2s_direct__(normalize_obj_kind_map_strings, normalize_obj_kind_map_i2s_direct, 0, 23, v);
}
