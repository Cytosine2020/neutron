#include "neutron_utility.hpp"
#include "riscv_linux.hpp"

using namespace neutron;


extern char **environ;

using xlen = riscv_isa::xlen_trait;


class Core : public LinuxHart<Core, xlen> {
public:
    Core(UXLenT hart_id, LinuxProgram<xlen> &mem) : LinuxHart<Core, xlen>{hart_id, mem} {}
};


int main(int argc, char **argv) {
    if (argc < 2) neutron_abort("receive one file name!");

    LinuxProgram<xlen> mem{};

    if (!mem.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");

    Core core{0, mem};
    core.start();

    exit(mem.exit_value);
}
