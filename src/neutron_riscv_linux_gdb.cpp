#include "neutron_utility.hpp"
#include "riscv_linux_gdb.hpp"

using namespace neutron;

extern char **environ;

class Core : public LinuxGDBHart<Core> {
public:
    Core(UXLenT hart_id, LinuxProgram<> &mem, u32 port) : LinuxGDBHart<Core>{hart_id, mem, port} {}
};

int main(int argc, char **argv) {
    if (argc < 2) neutron_abort("receive one file name!");

    LinuxProgram<> mem{true};

    if (!mem.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");

    Core core{0, mem, 6789};
    core.start();
}
