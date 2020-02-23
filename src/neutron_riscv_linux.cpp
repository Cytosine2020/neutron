#include <fcntl.h>
#include "neutron_utility.hpp"
#include "riscv_linux.hpp"

using namespace neutron;


class Core : public LinuxHart<Core> {
public:
    Core(UXLenT hart_id, LinuxProgram<> &mem) : LinuxHart<Core>{hart_id, mem} {}
};


int main(int argc, char **argv) {
    if (argc != 2) neutron_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) neutron_abort("open file failed!");

    MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) neutron_abort("memory map file failed!");

    LinuxProgram<> mem{};
    if (!mem.load_elf(visitor)) neutron_abort("ELF file broken!");

    Core core{0, mem};
    core.start();

    if (close(fd) != 0) neutron_abort("Close file failed!");
}
