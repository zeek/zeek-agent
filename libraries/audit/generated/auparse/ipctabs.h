/* This is a generated file, see Makefile.am for its inputs. */
static const char ipc_strings[] = "msgctl\0msgget\0msgrcv\0msgsnd\0semctl\0semget\0semop\0semtimedop\0shmat\0shmctl\0"
	"shmdt\0shmget";
static const unsigned ipc_i2s_direct[] = {
	42,35,28,48,-1u,-1u,-1u,-1u,-1u,-1u,
	21,14,7,0,-1u,-1u,-1u,-1u,-1u,-1u,
	59,72,78,65,
};
static const char *ipc_i2s(int v) {
	return i2s_direct__(ipc_strings, ipc_i2s_direct, 1, 24, v);
}
