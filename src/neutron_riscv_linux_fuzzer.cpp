#include <fcntl.h>

#include "neutron_utility.hpp"
#include "riscv_blocking.hpp"
#include "riscv_linux_fuzzer.hpp"
#include "dominator_tree.hpp"

using namespace neutron;


using UXLenT = riscv_isa::xlen_trait::UXLenT;
using XLenT = riscv_isa::xlen_trait::XLenT;


class RecordCompare { // todo: record not synchronized
private:
    class Status {
    public:
        std::vector<BranchRecord>::iterator ptr, end;
        std::vector<UXLenT> stack;

        explicit Status(std::vector<BranchRecord> &record) : ptr{record.begin()}, end{record.end()}, stack{} {}

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

        bool terminate() { return ptr == end; }

        bool step(UXLenT stack_top = 0) {
            bool ret = true;

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
                        if (is_link(ptr->get_jalr_rs1()) && ptr->get_jalr_rd() != ptr->get_jalr_rs1()) {
                            stack_seek(ptr->get_target());
                            if (ptr->get_target() == stack_top)
                                ret = false;
                        }

                        stack.emplace_back(ptr->address + riscv_isa::JALRInst::INST_WIDTH);
                    } else {
                        if (is_link(ptr->get_jalr_rs1())) {
                            stack_seek(ptr->get_target());
                            if (ptr->get_target() == stack_top)
                                ret = false;
                        }
                    }
                    break;
                default:
                    neutron_unreachable("unknown type");
            }

            ++ptr;
            return ret;
        }

        void break_within_function(UXLenT addr) {
            UXLenT stack_top = stack.back();

            while (!terminate()) {
                if (ptr->address == addr) break;

                if (!step(stack_top)) break;
            }
        }
    };

    Status origin, modified;
    std::map<UXLenT, UXLenT> &sync_point;
    std::vector<UXLenT> affected_address;
    UXLenT sync_address; // zero stands for return to caller
    bool sync;

    static bool is_link(usize reg) { return reg == 1 || reg == 5; }

    template<typename OP>
    void compare_record_branch() {
        if (origin.ptr->get_op1() != modified.ptr->get_op1() || origin.ptr->get_op2() != modified.ptr->get_op2())
            affected_address.emplace_back(origin.ptr->address);

        if (OP::op(origin.ptr->get_op1(), origin.ptr->get_op2()) !=
            OP::op(modified.ptr->get_op1(), modified.ptr->get_op2())) {
            sync_address = sync_point.find(origin.ptr->address)->second;
            sync = false;
        }
    }

    RecordCompare(std::vector<BranchRecord> &origin, std::vector<BranchRecord> &modified,
                  std::map<UXLenT, UXLenT> &sync_point) :
            origin{origin}, modified{modified}, sync_point{sync_point}, affected_address{}, sync_address{0},
            sync{true} {}

    std::vector<UXLenT> compare() {
        while (true) {
            if (modified.terminate()) {
                while (!origin.terminate()) {
                    origin.step(); // todo: finish origin if modified finished
                }
            }

            if (origin.terminate()) break;

            if (sync) {
                if (origin.ptr->address != modified.ptr->address) neutron_abort("unexpected");
                if (origin.ptr->type != modified.ptr->type) neutron_abort("unexpected");

                switch (origin.ptr->type) {
                    case BranchRecord::BEQ:
                        compare_record_branch<riscv_isa::operators::EQ<>>();
                        break;
                    case BranchRecord::BNE:
                        compare_record_branch<riscv_isa::operators::NE<>>();
                        break;
                    case BranchRecord::BLT:
                        compare_record_branch<riscv_isa::operators::LT<>>();
                        break;
                    case BranchRecord::BGE:
                        compare_record_branch<riscv_isa::operators::GE<>>();
                        break;
                    case BranchRecord::BLTU:
                        compare_record_branch<riscv_isa::operators::LTU<>>();
                        break;
                    case BranchRecord::BGEU:
                        compare_record_branch<riscv_isa::operators::GEU<>>();
                        break;
                    case BranchRecord::JAL:
                        break;
                    case BranchRecord::JALR:
                        if (origin.ptr->get_target() != modified.ptr->get_target()) {
                            affected_address.emplace_back(origin.ptr->address);
                            sync_address = 0;
                            sync = false;
                        }
                        break;
                    default:
                        neutron_unreachable("unknown type");
                }

                origin.step();
                modified.step();
            } else {
                origin.break_within_function(sync_address);
                modified.break_within_function(sync_address);
                sync = true;
            }
        }

        return std::move(affected_address);
    }

public:

    static std::vector<UXLenT> build(std::vector<BranchRecord> &origin, std::vector<BranchRecord> &modified,
                                     std::map<UXLenT, UXLenT> &sync_point) {
        return RecordCompare{origin, modified, sync_point}.compare();
    }
};


int main(int argc, char **argv) {
    if (argc != 2) neutron_abort("receive one file name!");

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
        auto &section = elf_header->sections(visitor)[func.section_header_index];

        void *start = visitor.address((func.value - section.address) + section.offset, func.size);
        if (start == nullptr) neutron_abort("ELF file broken!");

        auto blocks = BlockVisitor::build(func.value, start, func.size);
        auto pos_dominator = PosDominatorTree<UXLenT>::build(blocks, 0);

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

    auto affected_address = RecordCompare::build(origin_record, modified_record, sync_point);

    std::cout << std::hex;
    for (auto &item: affected_address) {
        std::cout << item << std::endl;
    }
    std::cout << std::dec;

    if (close(fd) != 0) neutron_abort("Close file failed!");
}
