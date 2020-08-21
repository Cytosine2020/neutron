#include "neutron_utility.hpp"
#include "riscv_linux.hpp"

using namespace neutron;


extern char **environ;

class Core : public LinuxHart<Core> {
public:
    Core(UXLenT hart_id, LinuxProgram<> &mem) : LinuxHart<Core>{hart_id, mem} {}
};


int main(int argc, char **argv) {
    if (argc < 2) neutron_abort("receive one file name!");

    LinuxProgram<> mem{};

    if (!mem.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");

    Core core{0, mem};
    core.start();

    exit(mem.exit_value);
}
