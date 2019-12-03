/* This is a generated file, see Makefile.am for its inputs. */
static const char cap_strings[] = "audit_control\0audit_read\0audit_write\0block_suspend\0chown\0dac_override\0dac_read_search\0fowner\0fsetid\0ipc_lock\0"
	"ipc_owner\0kill\0lease\0linux_immutable\0mac_admin\0mac_override\0mknod\0net_admin\0net_bind_service\0net_broadcast\0"
	"net_raw\0setfcap\0setgid\0setpcap\0setuid\0sys_admin\0sys_boot\0sys_chroot\0sys_module\0sys_nice\0"
	"sys_pacct\0sys_ptrace\0sys_rawio\0sys_resource\0sys_time\0sys_tty_config\0syslog\0wake_alarm";
static const unsigned cap_i2s_direct[] = {
	51,57,70,86,93,119,232,247,239,130,
	185,202,175,216,100,109,284,325,273,314,
	304,254,264,295,335,348,357,169,124,25,
	0,224,156,146,372,379,37,14,
};
static const char *cap_i2s(int v) {
	return i2s_direct__(cap_strings, cap_i2s_direct, 0, 37, v);
}
