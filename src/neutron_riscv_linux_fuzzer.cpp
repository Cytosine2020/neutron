#include <iostream>

#include "neutron_utility.hpp"
#include "riscv_linux_fuzzer.hpp"


using namespace neutron;


extern char **environ;

using xlen = riscv_isa::xlen_trait;


void create_tmp_dir() {
    int tmp_fd = open("/tmp", O_DIRECTORY);
    if (tmp_fd == -1) {
        neutron_abort("unexpected open failed!");
    }

    if (mkdirat(tmp_fd, "neutron", 0755) != 0 && errno != EEXIST) {
        neutron_abort("unexpected mkdirat failed!");
    }

    close(tmp_fd);
}


int main(int argc, char **argv) {
    if (argc < 2) neutron_abort("receive one file name!");

    create_tmp_dir();

    elf::MappedFileVisitor visitor = elf::MappedFileVisitor::open_elf(argv[1]);
    if (visitor.get_fd() == -1) neutron_abort("memory map file failed!");

    auto *elf_header = elf::ELFHeader<xlen::UXLenT>::read(visitor);
    if (elf_header == nullptr) neutron_abort("ELF header broken!");

    LinuxFuzzerCore<xlen>::InputT origin_input{};
    LinuxProgram<xlen> mem1{true};
    if (!mem1.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");
    auto origin_record = LinuxFuzzerCore<xlen>{0, mem1, origin_input}.start();

    std::vector<std::pair<Array<char>, xlen::UXLenT>> result{};
    if (!get_dynamic_library(visitor, mem1, result)) neutron_warn("Failed to get debug info!");

    const char *system_root = getenv("RISCV_SYSROOT");

    std::map<xlen::UXLenT, xlen::UXLenT> sync_point{};
    if (!get_sync_point<xlen>(visitor, sync_point, mem1.elf_shift)) neutron_unreachable("already checked!");

    for (auto &item: result) {
        const char *name = item.first.begin();
        xlen::UXLenT shift = item.second;
        std::stringstream buf{};
        buf << system_root << name;

        elf::MappedFileVisitor lib_visitor = elf::MappedFileVisitor::open_elf(buf.str().c_str());
        get_sync_point<xlen>(lib_visitor, sync_point, shift);
    }

    for (auto &item: origin_input) {
        auto &name = item.first;
        u64 size = std::min(item.second.size(), 10ul);

        for (usize i = 0; i < size; ++i) {
            LinuxFuzzerCore<xlen>::InputT modified_input = origin_input;
            modified_input[name][i] = static_cast<u8>(rand());

            LinuxProgram<xlen> mem2{};
            if (!mem2.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");
            auto modified_record = LinuxFuzzerCore<xlen>{0, mem2, modified_input}.start();

            auto affected_address = RecordCompare<xlen>::build(origin_record, modified_record, sync_point);

            std::cout << name << ", " << i << ": " << std::hex;
            for (auto &addr: affected_address) {
                std::cout << addr << ' ';
            }
            std::cout << std::dec << std::endl;
        }
    }
}
