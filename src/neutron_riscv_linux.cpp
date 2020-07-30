#include <fcntl.h>
#include "neutron_utility.hpp"
#include "riscv_linux.hpp"

using namespace neutron;


class Core : public LinuxHart<Core> {
public:
    Core(UXLenT hart_id, LinuxProgram<> &mem) : LinuxHart<Core>{hart_id, mem} {}
};


int main(int argc, char **argv, char **envp) {
    if (argc < 2) neutron_abort("receive one file name!");

#if defined(__linux__)
    int fd = open(argv[1], O_RDONLY | F_SHLCK);
#elif defined(__APPLE__)
    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
#else
#error "OS not supported"
#endif

    if (fd == -1) neutron_abort("open file failed!");

    elf::MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) neutron_abort("memory map file failed!");

    LinuxProgram<> mem{};
    if (!mem.load_elf(visitor, argc - 1, ++argv, envp)) neutron_abort("ELF file broken!");

    Core core{0, mem};
    core.start();
}
