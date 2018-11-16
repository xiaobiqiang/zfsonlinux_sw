
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
	int fd;
	char mode;
	int ret;
	fd = open("/dev/vmpt3sas_mm_dev", O_RDWR);
	if (-1 == fd){
		printf("open vmpt3sas_mm_dev failed \n");
		return -1;
	}
	
	printf("open vmpt3sas_mm_dev sucess \n");
	if(argc==2){
		mode = *(argv[1]);
		printf("mode = %x\n",(unsigned char)mode);
		if (mode =='1'){
			ret = ioctl(fd,1,NULL);
		}	
	}
	close(fd);
	return ret;
}
