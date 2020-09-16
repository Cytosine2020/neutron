#include "neutron_utility.hpp"
#include "riscv_linux.hpp"
#include "neutron_argument.hpp"

using namespace neutron;


extern char **environ;


int main(int argc, char **argv) {
    using xlen = riscv_isa::xlen_trait;

    if (argc < 2) { neutron_abort("receive one file name!"); }

    auto pair = process_argument(argc, argv, environ);

    LinuxProgram<xlen> mem{};

    if (!mem.load_elf(argv[1], pair.first, pair.second)) { exit(1); }

    LinuxHart<xlen> core{0, mem};

//    core.goto_main();
//
//    mem.dump_map(std::cout);

    core.start();

    exit(mem.exit_value);
}
