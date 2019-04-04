#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int hostid;
	int ret;

	if (argc < 2) {
		printf("Ussage: sethostid hostid\n");
		return (-1);
	}

	hostid = atoi(argv[1]);
	ret = sethostid(hostid);
	
	if (ret == 0)
		printf("sethostid %d success\n", hostid);
	else
		printf("sethostid %d failed, error %d\n", hostid, ret);

	return (ret);
}
