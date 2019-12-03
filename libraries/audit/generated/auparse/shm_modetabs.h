/* This is a generated file, see Makefile.am for its inputs. */
static const char shm_mode_strings[] = "SHM_DEST\0SHM_HUGETLB\0SHM_LOCKED\0SHM_NORESERVE";
static const struct transtab shm_mode_table[] = {
	{512,0},{1024,21},{2048,9},{4096,32},
};
#define SHM_MODE_NUM_ENTRIES (sizeof(shm_mode_table) / sizeof(*shm_mode_table))
