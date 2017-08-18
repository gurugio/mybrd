#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>

int main(void)
{
    int fd;
    char buf[40960];
    ssize_t ret;

    fd = open("/dev/mybrd", O_RDWR);
    if (fd < 0) {
        perror("fail to open");
        return 1;
    }

    ret = read(fd, buf, 40960);
    printf("read %d-bytes\n", (int)ret);

    printf("\n\n------------------- start ioctl -----------\n");
    ioctl(fd, 0x1234);
    printf("------------------- end ioctl -----------\n\n");


    memset(buf, 0xa5, 40960);
    lseek(fd, 0, SEEK_SET);
    ret = write(fd, buf, 40960);
    printf("write %d-bytes\n", (int)ret);
    
    printf("\n\n------------------- start ioctl -----------\n");
    ioctl(fd, 0x1234);
    printf("------------------- end ioctl -----------\n\n");

    close(fd);

    return 0;
}
