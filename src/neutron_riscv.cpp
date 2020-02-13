#include <fcntl.h>
#include "riscv_linux.hpp"

using namespace neutron;


int main(int argc, char **argv) {
    if (argc != 2) riscv_isa_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) riscv_isa_abort("open file failed!");

    MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) riscv_isa_abort("memory map file failed!");

    LinuxProgram<> mem{};
    if (!mem.load_elf(visitor)) riscv_isa_abort("ELF file broken!");

    LinuxHart core{0, mem};
    core.start();

    if (close(fd) != 0) riscv_isa_abort("Close file failed!");
}
