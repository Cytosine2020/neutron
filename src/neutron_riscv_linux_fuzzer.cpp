#include <fcntl.h>

#include "neutron_utility.hpp"
#include "riscv_blocking.hpp"
#include "riscv_linux_fuzzer.hpp"
#include "dominator_tree.hpp"

using namespace neutron;


using UXLenT = riscv_isa::xlen_trait::UXLenT;
using XLenT = riscv_isa::xlen_trait::XLenT;


class RecordCompare { // todo: record not synchronized
public:
    using BranchRecordPtr = std::vector<BranchRecord>::iterator;

private:
    class Status {
    public:
        std::vector<BranchRecord> &record;
        BranchRecordPtr ptr;
        std::vector<UXLenT> stack;

        explicit Status(std::vector<BranchRecord> &record) : record{record}, ptr{record.begin()}, stack{} {}

        void stack_seek(UXLenT target) {
            if (target != stack.back()) neutron_abort("");
            stack.pop_back();

//    isize i = stack.size() - 1;
//    for (; i >= 0; --i)
//        if (target == stack[i])
//            break;
//
//    if (i >= 0)
//        stack.resize(i, 0);
        }

        bool terminate() { return ptr == record.end(); }

        void step() {
            switch (ptr->type) {
                case BranchRecord::BEQ:
                case BranchRecord::BNE:
                case BranchRecord::BLT:
                case BranchRecord::BGE:
                case BranchRecord::BLTU:
                case BranchRecord::BGEU:
                    break;
                case BranchRecord::JAL:
                    if (is_link(ptr->get_jal_rd()))
                        stack.emplace_back(ptr->address + riscv_isa::JALInst::INST_WIDTH);

                    break;
                case BranchRecord::JALR:
                    if (is_link(ptr->get_jalr_rd())) {
                        if (is_link(ptr->get_jalr_rs1()) && ptr->get_jalr_rd() != ptr->get_jalr_rs1())
                            stack_seek(ptr->get_target());
                        stack.emplace_back(ptr->address + riscv_isa::JALRInst::INST_WIDTH);
                    } else {
                        if (is_link(ptr->get_jalr_rs1()))
                            stack_seek(ptr->get_target());
                    }
                    break;
                default:
                    neutron_unreachable("unknown type");
            }

            ++ptr;
        }

        bool step_within_function(UXLenT stack_top) {
            switch (ptr->type) {
                case BranchRecord::BEQ:
                case BranchRecord::BNE:
                case BranchRecord::BLT:
                case BranchRecord::BGE:
                case BranchRecord::BLTU:
                case BranchRecord::BGEU:
                    break;
                case BranchRecord::JAL:
                    if (is_link(ptr->get_jal_rd()))
                        stack.emplace_back(ptr->address + riscv_isa::JALInst::INST_WIDTH);

                    break;
                case BranchRecord::JALR:
                    if (is_link(ptr->get_jalr_rd())) {
                        bool flag = is_link(ptr->get_jalr_rs1()) && ptr->get_jalr_rd() != ptr->get_jalr_rs1();

                        if (flag) stack_seek(ptr->get_target());

                        stack.emplace_back(ptr->address + riscv_isa::JALRInst::INST_WIDTH);

                        if (flag && ptr->get_target() == stack_top) {
                            ++ptr;
                            return false;
                        }
                    } else {
                        if (is_link(ptr->get_jalr_rs1())) {
                            stack_seek(ptr->get_target());
                            if (ptr->get_target() == stack_top) {
                                ++ptr;
                                return false;
                            }
                        }
                    }
                    break;
                default:
                    neutron_unreachable("unknown type");
            }

            ++ptr;
            return true;
        }

        void step_out() {
            UXLenT stack_top = stack.back();

            while (!terminate()) {
                if (!step_within_function(stack_top)) break;
            }
        }

        void break_at(UXLenT addr) {
            UXLenT stack_top = stack.back();

            while (!terminate()) {
                if (ptr->address == addr) return;

                if (!step_within_function(stack_top)) break;
            }
        }
    };

    Status origin, modified;
    std::map<UXLenT, UXLenT> &sync_point;
    UXLenT sync_address;
    enum {
        STACK, ADDRESS, SYNC
    } sync;

    static bool is_link(usize reg) { return reg == 1 || reg == 5; }

    template<typename OP>
    void compare_record_branch() {
        if (origin.ptr->get_op1() != modified.ptr->get_op1() || origin.ptr->get_op2() != modified.ptr->get_op2())
            std::cout << std::hex << origin.ptr->address << std::dec << std::endl;

        if (OP::op(origin.ptr->get_op1(), origin.ptr->get_op2()) !=
            OP::op(modified.ptr->get_op1(), modified.ptr->get_op2())) {
            sync_address = sync_point.find(origin.ptr->address)->second;
            sync = ADDRESS;
        }
    }

public:
    RecordCompare(std::vector<BranchRecord> &origin, std::vector<BranchRecord> &modified,
                  std::map<UXLenT, UXLenT> &sync_point) :
            origin{origin}, modified{modified}, sync_point{sync_point}, sync_address{0}, sync{SYNC} {}

    void compare() {
        while (true) {
            if (modified.terminate()) {
                while (!origin.terminate()) {
                    origin.step(); // todo: finish origin if modified finished
                }
            }

            if (origin.terminate()) break;

            switch (sync) {
                case SYNC:
                    if (origin.ptr->address != modified.ptr->address) neutron_abort("unexpected");
                    if (origin.ptr->type != modified.ptr->type) neutron_abort("unexpected");

                    switch (origin.ptr->type) {
                        case BranchRecord::BEQ:
                            compare_record_branch<riscv_isa::operators::EQ<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::BNE:
                            compare_record_branch<riscv_isa::operators::NE<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::BLT:
                            compare_record_branch<riscv_isa::operators::LT<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::BGE:
                            compare_record_branch<riscv_isa::operators::GE<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::BLTU:
                            compare_record_branch<riscv_isa::operators::LTU<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::BGEU:
                            compare_record_branch<riscv_isa::operators::GEU<riscv_isa::xlen_trait>>();
                            break;
                        case BranchRecord::JAL:
                            break;
                        case BranchRecord::JALR:
                            if (origin.ptr->get_target() != modified.ptr->get_target()) {
                                std::cout << std::hex << origin.ptr->address << std::dec << std::endl;
                                sync = STACK;
                            }
                            break;
                        default:
                            neutron_unreachable("unknown type");
                    }

                    origin.step();
                    modified.step();
                    break;
                case STACK:
                    origin.step_out();
                    modified.step_out();
                    sync = SYNC;
                    break;
                case ADDRESS:
                    origin.break_at(sync_address);
                    modified.break_at(sync_address);
                    sync = SYNC;
                    break;
                default:
                    neutron_unreachable("unknown type");
            }
        }
    }
};


int main(int argc, char **argv) {
    if (argc != 2) neutron_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) neutron_abort("open file failed!");

    elf::MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) neutron_abort("memory map file failed!");

    auto *elf_header = elf::ELF32Header::read(visitor);
    if (elf_header == nullptr) neutron_abort("ELF header broken!");
    if (elf_header->file_type != elf::ELF32Header::EXECUTABLE) neutron_abort("ELF file not executable!");

    std::map<u32, elf::ELF32SymbolTableHeader::SymbolTableEntry &> objects, functions;

    for (auto &section: elf_header->sections(visitor)) {
        auto *symbol_table_header = elf::ELF32SectionHeader::cast<elf::ELF32SymbolTableHeader>(&section, visitor);
        if (symbol_table_header == nullptr) continue;

        for (auto &symbol: symbol_table_header->get_symbol_table(visitor)) {
            switch (symbol.get_type()) {
                case elf::ELF32SymbolTableHeader::OBJECT:
                    objects.emplace(symbol.value, symbol);
                    break;
                case elf::ELF32SymbolTableHeader::FUNC:
                    functions.emplace(symbol.value, symbol);
                    break;
                default:
                    break;
            }
        }
    }

    std::map<UXLenT, UXLenT> sync_point{};

    for (auto &function: functions) {
        auto &func = function.second;
        auto section = elf_header->sections(visitor)[func.section_header_index];

        void *start = visitor.address((func.value - section.address) + section.offset, func.size);
        if (start == nullptr) neutron_abort("ELF file broken!");

        auto blocks = BlockVisitor{}.blocking(func.value, start, func.size);
        auto pos_dominator = DominatorTree<UXLenT, true>{blocks, 0}.semi_nca();

        sync_point.insert(pos_dominator.begin(), pos_dominator.end());
    }

    std::vector<u8> origin_input{};

    LinuxProgram<> mem1{};
    if (!mem1.load_elf(visitor)) neutron_abort("ELF file broken!");
    auto origin_record = LinuxFuzzerHart{0, mem1, origin_input}.start();

    std::vector<u8> modified_input = origin_input;
    modified_input[0] = static_cast<u8>(rand());

    LinuxProgram<> mem2{};
    if (!mem2.load_elf(visitor)) neutron_abort("ELF file broken!");
    auto modified_record = LinuxFuzzerHart{0, mem2, modified_input}.start();

    RecordCompare{origin_record, modified_record, sync_point}.compare();

    if (close(fd) != 0) neutron_abort("Close file failed!");
}
