#include <fcntl.h>
#include <iostream>


void print_file_mode(int fd) {
    if (fcntl(fd, F_GETFD)) {
        std::cout << "FD_CLOEXEC" << std::endl;
    }

    int flag = fcntl(fd, F_GETFL);

#define DISPLAY(f, o) \
    if ((f & o) == o) { \
        std::cout << #o << std::endl; \
    }

    if ((flag & O_WRONLY) == O_WRONLY) {
        std::cout << "O_WRONLY" << std::endl;
    } else if ((flag & O_RDWR) == O_RDWR) {
        std::cout << "O_RDWR" << std::endl;
    } else {
        std::cout << "O_RDONLY" << std::endl;
    }

    DISPLAY(flag, O_CREAT)
    DISPLAY(flag, O_EXCL)
    DISPLAY(flag, O_NOCTTY)
    DISPLAY(flag, O_TRUNC)
    DISPLAY(flag, O_APPEND)
    DISPLAY(flag, O_NONBLOCK)
    DISPLAY(flag, O_DSYNC)
    DISPLAY(flag, O_ASYNC)
    DISPLAY(flag, O_DIRECT)
    DISPLAY(flag, O_LARGEFILE)
    DISPLAY(flag, O_DIRECTORY)
    DISPLAY(flag, O_NOFOLLOW)
    DISPLAY(flag, O_NOATIME)
    DISPLAY(flag, O_CLOEXEC)
    DISPLAY(flag, O_SYNC)
    DISPLAY(flag, O_PATH)
    DISPLAY(flag, O_TMPFILE)

    std::cout << std::endl;
}

int main() {
    print_file_mode(0);
    print_file_mode(1);
    print_file_mode(2);
}