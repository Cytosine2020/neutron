#include <iostream>

#include "neutron_utility.hpp"
#include "riscv_linux_fuzzer.hpp"
#include "fuzzer/seed_pool.hpp"
#include "fuzzer/branch_table.hpp"


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

    SeedPool::SeedT origin_seed{};
    LinuxProgram<xlen> mem1{};
    if (!mem1.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");
    auto origin_record = LinuxFuzzerCore<xlen>{0, mem1, origin_seed}.start();

    std::vector<std::pair<Array<char>, xlen::UXLenT>> result{};
    if (!get_dynamic_library(visitor, mem1, result)) neutron_warn("Failed to get debug info!");

    const char *system_root = getenv("RISCV_SYSROOT");

    BlockVisitor::BranchMapT block{}, indirect{};

    std::map<xlen::UXLenT, xlen::UXLenT> sync_point{};
    if (!get_sync_point<xlen>(visitor, sync_point, mem1.elf_shift, block, indirect)) {
        neutron_unreachable("The validation of elf file has been already checked!");
    }

    for (auto &item: result) {
        const char *name = item.first.begin();
        xlen::UXLenT shift = item.second;
        std::stringstream buf{};
        buf << system_root << name;

        elf::MappedFileVisitor lib_visitor = elf::MappedFileVisitor::open_elf(buf.str().c_str());
        if (!get_sync_point<xlen>(lib_visitor, sync_point, shift, block, indirect)) {
            neutron_unreachable("The validation of elf file has been already checked!");
        }
    }

    SeedPool seed_pool{};
    BranchTable<xlen> branch_table{std::move(block), std::move(indirect)};

    branch_table.add_seed(seed_pool.insert_seed(origin_seed), origin_record);

    /// find out which file is interesting

    std::random_device rand{};
    std::map<usize, std::set<std::string>> file_priority{};

    for (auto &item: origin_seed) {
        auto &name = item.first;
        auto origin_content = item.second;

        std::unordered_set<xlen::UXLenT> affected_address{};

        for (usize i = 0; i < 10; ++i) {
            auto modified_seed = origin_seed;
            auto modified_content = origin_content->shallow_copy();

            u64 pos = (1 << i) % modified_content.size();

            u8 old_val = modified_content[pos];
            u8 new_val = static_cast<u8>(rand());
            while (new_val == old_val) { new_val = static_cast<u8>(rand()); }

            modified_content[pos] = static_cast<u8>(rand());

            modified_seed[name] = std::make_shared<Array<u8>>(std::move(modified_content));

            LinuxProgram<xlen> mem2{};
            if (!mem2.load_elf(argv[1], argc - 1, argv + 1, environ)) {
                neutron_abort("ELF file broken!");
            }

            auto modified_record = LinuxFuzzerCore<xlen>{0, mem2, modified_seed}.start();
            auto address = RecordCompare<xlen>::build(origin_record, modified_record, sync_point);
            affected_address.insert(address.begin(), address.end());

            branch_table.add_seed(seed_pool.insert_seed(std::move(modified_seed)), modified_record);
        }

        file_priority[affected_address.size()].emplace(name);
    }

    /// fuzz each file

    for (auto item = file_priority.rbegin(); item != file_priority.rend(); ++item) {
        for (auto &name: item->second) {
            const auto origin_content = origin_seed.find(name)->second;
            usize size = origin_content->size();

            std::map<xlen::UXLenT, std::set<u64>> input_dependency;

            for (usize i = 0; i < size; ++i) {
                auto modified_seed = origin_seed;
                auto modified_content = origin_content->shallow_copy();

                u8 old_val = modified_content[i];
                u8 new_val = static_cast<u8>(rand());
                while (new_val == old_val) { new_val = static_cast<u8>(rand()); }

                modified_content[i] = static_cast<u8>(rand());

                modified_seed[name] = std::make_shared<Array<u8>>(std::move(modified_content));

                LinuxProgram<xlen> mem2{};
                if (!mem2.load_elf(argv[1], argc - 1, argv + 1, environ)) {
                    neutron_abort("ELF file broken!");
                }

                auto modified_record = LinuxFuzzerCore<xlen>{0, mem2, modified_seed}.start();
                auto address = RecordCompare<xlen>::build(origin_record, modified_record, sync_point);

                for (auto addr: address) {
                    input_dependency[addr].emplace(i);
                }

                branch_table.add_seed(seed_pool.insert_seed(std::move(modified_seed)), modified_record);
            }

            for (auto &addr: input_dependency) {
                std::cout << std::hex << addr.first << ": ";

                for (auto &offset: addr.second) {
                    std::cout << offset << ' ';
                }
                std::cout << std::dec << std::endl;
            }
        }

        break;
    }
}
