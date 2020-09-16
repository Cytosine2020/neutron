#ifndef NEUTRON_RISCV_LINUX_FUZZER_HPP
#define NEUTRON_RISCV_LINUX_FUZZER_HPP


#include <cerrno>
#include <fcntl.h>

#include <iostream>
#include <vector>
#include <random>
#include <unordered_map>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "neutron_utility.hpp"
#include "riscv_linux_program.hpp"
#include "riscv_linux.hpp"
#include "linux_std.hpp"
#include "riscv_blocking.hpp"
#include "dominator_tree.hpp"
#include "fuzzer/seed_pool.hpp"


namespace neutron {
    template<typename xlen>
    struct BranchRecord {
    public:
        using UXLenT = typename xlen::UXLenT;

        enum {
            BEQ, BNE, BLT, BGE, BLTU, BGEU, JAL, JALR,
        } type;

        UXLenT address;

        union {
            struct {
                UXLenT op1, op2;
            } branch;
            struct {
                u8 rd;
            } jal;
            struct {
                UXLenT target;
                u8 rd, rs1;
            } jalr;
        } inner;

        static BranchRecord beq(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BEQ, address, {.branch = {op1, op2}}};
        }

        static BranchRecord bne(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BNE, address, {.branch = {op1, op2}}};
        }

        static BranchRecord blt(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BLT, address, {.branch = {op1, op2}}};
        }

        static BranchRecord bge(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BGE, address, {.branch = {op1, op2}}};
        }

        static BranchRecord bltu(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BLTU, address, {.branch = {op1, op2}}};
        }

        static BranchRecord bgeu(UXLenT address, UXLenT op1, UXLenT op2) {
            return BranchRecord{BGEU, address, {.branch = {op1, op2}}};
        }

        static BranchRecord jal(UXLenT address, u8 link) {
            return BranchRecord{JAL, address, {.jal = {link}}};
        }

        static BranchRecord jalr(UXLenT address, UXLenT target, u8 rd, u8 rs1) {
            return BranchRecord{JALR, address, {.jalr = {target, rd, rs1}}};
        }

        UXLenT get_op1() const { return inner.branch.op1; }

        UXLenT get_op2() const { return inner.branch.op2; }

        UXLenT get_target() const { return inner.jalr.target; }

        u8 get_jal_rd() const { return inner.jal.rd; }

        u8 get_jalr_rd() const { return inner.jalr.rd; }

        u8 get_jalr_rs1() const { return inner.jalr.rs1; }
    };

    template<typename xlen>
    class RecordCompare {
    public:
        using UXLenT = typename xlen::UXLenT;
        using XLenT = typename xlen::XLenT;

        using BranchRecordT = std::vector<BranchRecord<xlen>>;

    private:
        class Status {
        public:
            typename BranchRecordT::iterator ptr, end;
            std::vector<UXLenT> stack;

            explicit Status(BranchRecordT &record) :
                    ptr{record.begin()}, end{record.end()}, stack{0} {}

            void stack_seek(UXLenT target) {
                if (stack.back() != target && stack.back() != 0) neutron_abort("");
                stack.pop_back();

//    isize i = stack.size() - 1;
//    for (; i >= 0; --i)
//        if (target == stack[i])
//            break;
//
//    if (i >= 0)
//        stack.resize(i, 0);
            }

            bool terminate() const { return ptr == end || stack.empty(); }

            void step() {
                switch (ptr->type) {
                    case BranchRecord<xlen>::BEQ:
                    case BranchRecord<xlen>::BNE:
                    case BranchRecord<xlen>::BLT:
                    case BranchRecord<xlen>::BGE:
                    case BranchRecord<xlen>::BLTU:
                    case BranchRecord<xlen>::BGEU:
                        break;
                    case BranchRecord<xlen>::JAL:
                        if (is_link(ptr->get_jal_rd()))
                            stack.emplace_back(ptr->address + riscv_isa::JALInst::INST_WIDTH);

                        break;
                    case BranchRecord<xlen>::JALR:
                        if (is_link(ptr->get_jalr_rd())) {
                            if (is_link(ptr->get_jalr_rs1()) && ptr->get_jalr_rd() != ptr->get_jalr_rs1()) {
                                stack_seek(ptr->get_target());
                            }

                            stack.emplace_back(ptr->address + riscv_isa::JALRInst::INST_WIDTH);
                        } else {
                            if (is_link(ptr->get_jalr_rs1())) {
                                stack_seek(ptr->get_target());
                            }
                        }
                        break;
                    default:
                        neutron_unreachable("unknown type");
                }

                ++ptr;
            }

            void break_address(UXLenT addr) {
                UXLenT stack_size = stack.size();

                if (addr == 0) {
                    while (!terminate() && stack.size() >= stack_size) {
                        step();
                    }
                } else {
                    while (!terminate()) {
                        if (stack.size() == stack_size && ptr->address == addr) {
                            break;
                        }

                        step();
                    }
                }
            }
        };

        Status origin, modified;
        const std::map<UXLenT, UXLenT> &sync_point;
        std::unordered_set<UXLenT> affected_address;
        UXLenT sync_address; // zero stands for return to caller
        bool sync;

        static bool is_link(usize reg) { return reg == 1 || reg == 5; }

        template<typename OP>
        void compare_record_branch() {
            if (origin.ptr->get_op1() != modified.ptr->get_op1() || origin.ptr->get_op2() != modified.ptr->get_op2())
                affected_address.emplace(origin.ptr->address);

            if (OP::op(origin.ptr->get_op1(), origin.ptr->get_op2()) !=
                OP::op(modified.ptr->get_op1(), modified.ptr->get_op2())) {
                sync_address = sync_point.find(origin.ptr->address)->second;
                sync = false;
            }
        }

        RecordCompare(BranchRecordT &origin, BranchRecordT &modified,
                      const std::map<UXLenT, UXLenT> &sync_point) :
                origin{origin}, modified{modified}, sync_point{sync_point}, affected_address{}, sync_address{0},
                sync{true} {}

        std::unordered_set<UXLenT> compare() {
            while (true) {
                if (modified.terminate()) {
                    while (!origin.terminate()) {
                        origin.step();
                    }
                }

                if (origin.terminate()) break;

                if (sync) {
                    if (origin.ptr->address != modified.ptr->address) neutron_abort("unexpected");
                    if (origin.ptr->type != modified.ptr->type) neutron_abort("unexpected");

                    switch (origin.ptr->type) {
                        case BranchRecord<xlen>::BEQ:
                            compare_record_branch<riscv_isa::operators::EQ<xlen>>();
                            break;
                        case BranchRecord<xlen>::BNE:
                            compare_record_branch<riscv_isa::operators::NE<xlen>>();
                            break;
                        case BranchRecord<xlen>::BLT:
                            compare_record_branch<riscv_isa::operators::LT<xlen>>();
                            break;
                        case BranchRecord<xlen>::BGE:
                            compare_record_branch<riscv_isa::operators::GE<xlen>>();
                            break;
                        case BranchRecord<xlen>::BLTU:
                            compare_record_branch<riscv_isa::operators::LTU<xlen>>();
                            break;
                        case BranchRecord<xlen>::BGEU:
                            compare_record_branch<riscv_isa::operators::GEU<xlen>>();
                            break;
                        case BranchRecord<xlen>::JAL:
                            break;
                        case BranchRecord<xlen>::JALR:
                            if (origin.ptr->get_target() != modified.ptr->get_target()) {
                                affected_address.emplace(origin.ptr->address);
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
                    origin.break_address(sync_address);
                    modified.break_address(sync_address);
                    sync = true;
                }
            }

            return std::move(affected_address);
        }

    public:

        static std::unordered_set<UXLenT> build(BranchRecordT &origin,
                                                BranchRecordT &modified,
                                                std::map<UXLenT, UXLenT> &sync_point) {
            return RecordCompare{origin, modified, sync_point}.compare();
        }
    };

    template<typename xlen>
    class LinuxFuzzerCore : public LinuxHart_<LinuxFuzzerCore<xlen>, xlen> {
    public:
        using SuperT = LinuxHart_<LinuxFuzzerCore, xlen>;

        using RetT = typename SuperT::RetT;
        using XLenT = typename SuperT::XLenT;
        using UXLenT = typename SuperT::UXLenT;
        using IntRegT = typename SuperT::IntRegT;
        using CSRRegT = typename SuperT::CSRRegT;

        using BranchRecordT = std::vector<BranchRecord<xlen>>;
        using InputT = SeedPool::SeedT;

    private:
        SuperT *super() { return this; }

        LinuxFuzzerCore *sub_type() { return this; }

        static std::string get_name_from_fd(int fd) {
            std::stringstream tmp{};
            tmp << "/proc/self/fd/" << fd;

            char buf[PATH_MAX]{};

            usize ret = readlink(tmp.str().c_str(), buf, PATH_MAX);

            return ret >= PATH_MAX ? "" : buf;
        }

        static std::string u64_to_string(u64 val) {
            char buf[17]{};

            for (usize i = 0; i < 16; ++i) {
                u64 c = val & 0b1111u;

                if (c <= 9) {
                    buf[i] = static_cast<char>(c + '0');
                } else {
                    buf[i] = static_cast<char>(c - 10 + 'a');
                }

                val >>= 4u;
            }

            return buf;
        }

    protected:
        BranchRecordT record;
        InputT &input;
        std::unordered_map<std::string, u64> file_map;
        std::unordered_map<int, int> shadow_fd_map;
        std::random_device rand;
        int tmp_fd;
        int null_fd;
        bool main;

    public:
        LinuxFuzzerCore(UXLenT hart_id, LinuxProgram<xlen> &mem, InputT &input) :
                SuperT{hart_id, mem}, record{}, input{input},
                file_map{}, shadow_fd_map{}, rand{}, tmp_fd{-1}, null_fd{-1}, main{false} {
            tmp_fd = open("/tmp/neutron", O_DIRECTORY);
            if (tmp_fd == -1) {
                neutron_abort("unexpected open failed!");
            }

            null_fd = open("/dev/null", O_RDWR);
            if (null_fd == -1) {
                neutron_abort("unexpected open failed!");
            }

            file_open(0);
        }

        RetT visit_jal_inst(const riscv_isa::JALInst *inst) {
            if (main) {
                record.emplace_back(BranchRecord<xlen>::jal(sub_type()->get_pc(), inst->get_rd()));
            }

            return super()->visit_jal_inst(inst);
        }

        RetT visit_jalr_inst(const riscv_isa::JALRInst *inst) {
            if (main) {
                usize rs1 = inst->get_rs1();
                XLenT imm = inst->get_imm();
                UXLenT target = get_bits<UXLenT, xlen::XLEN, 1, 1>(sub_type()->get_x(rs1) + imm);

                record.emplace_back(BranchRecord<xlen>::jalr(sub_type()->get_pc(), target, inst->get_rd(), rs1));
            }

            return super()->visit_jalr_inst(inst);
        }

        RetT visit_beq_inst(const riscv_isa::BEQInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::beq(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_beq_inst(inst);
        }

        RetT visit_bne_inst(const riscv_isa::BNEInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::bne(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_bne_inst(inst);
        }

        RetT visit_blt_inst(const riscv_isa::BLTInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::blt(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_blt_inst(inst);
        }

        RetT visit_bge_inst(const riscv_isa::BGEInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::bge(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_bge_inst(inst);
        }

        RetT visit_bltu_inst(const riscv_isa::BLTUInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::bltu(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_bltu_inst(inst);
        }

        RetT visit_bgeu_inst(const riscv_isa::BGEUInst *inst) {
            if (main) {
                UXLenT op1 = sub_type()->get_x(inst->get_rs1());
                UXLenT op2 = sub_type()->get_x(inst->get_rs2());

                record.emplace_back(BranchRecord<xlen>::bgeu(sub_type()->get_pc(), op1, op2));
            }

            return super()->visit_bgeu_inst(inst);
        }

        void file_open(int guest_fd) {
            int host_fd = super()->get_host_fd(guest_fd);

            struct ::stat tmp{};
            if (::fstat(host_fd, &tmp) == -1) {
                neutron_abort("unexpected stat failed!");
            }

            if (S_ISREG(tmp.st_mode)) {
                std::string name = get_name_from_fd(host_fd);
                if (name == "") {
                    neutron_abort("failed to get name of a file!");
                }

                int mode = ::fcntl(host_fd, F_GETFL);
                if (mode == -1) {
                    neutron_abort("unexpected fcntl failed!");
                }

                auto file_ptr = file_map.find(name);
                if (file_ptr == file_map.end()) {
                    auto ptr = input.find(name);
                    if (ptr == input.end()) {
                        Array<u8> content(tmp.st_size);

                        if (pread(host_fd, content.begin(), tmp.st_size, 0) != tmp.st_size) {
                            neutron_abort("unexpected read failed!");
                        }

                        ptr = input.emplace(name, std::make_shared<Array<u8>>(std::move(content))).first;
                    }

                    int fd = -1;
                    u64 num;

                    while (fd == -1) {
                        num = (static_cast<u64>(rand()) << 32u) + rand();

                        fd = openat(tmp_fd, u64_to_string(num).c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);

                        if (fd == -1 && errno != EEXIST) {
                            neutron_abort("unexpected open failed!");
                        }
                    }

                    auto content = ptr->second;

                    if (static_cast<u64>(pwrite(fd, content->begin(), content->size(), 0)) != content->size()) {
                        neutron_abort("unexpected write failed!");
                    }

                    if (fcntl(fd, F_SETFL, mode) == -1) {
                        neutron_abort("unexpected fcntl failed!");
                    }

                    file_map.emplace(name, num);
                    shadow_fd_map.emplace(guest_fd, fd);
                } else {
                    int fd = openat(tmp_fd, u64_to_string(file_ptr->second).c_str(), mode);

                    if (fd == -1) {
                        neutron_abort("unexpected open failed!");
                    }

                    shadow_fd_map.emplace(guest_fd, fd);
                }
            }
        }

        int get_host_fd(int fd) {
            if (fd < 0) { return fd; }

            if (fd == 1 || fd == 2) { return null_fd; }

            auto ptr = shadow_fd_map.find(fd);
            if (ptr == shadow_fd_map.end()) {
                return super()->get_host_fd(fd);
            } else {
                return ptr->second;
            }
        }

        XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
            XLenT ret = super()->sys_openat(dirfd, pathname, flags, mode);

            if (main && ret >= 0) {
                if ((flags & NEUTRON_O_CREAT) != NEUTRON_O_CREAT &&
                    (flags & NEUTRON_O_TRUNC) != NEUTRON_O_TRUNC) {
                    file_open(ret);
                }
            }

            return ret;
        }

        XLenT sys_close(int fd) {
            auto ptr = shadow_fd_map.find(fd);
            if (ptr != shadow_fd_map.end()) {
                close(ptr->second);
            }

            return super()->sys_close(fd);
        }

        BranchRecordT start() {
            if (sub_type()->goto_main()) {
                main = true;

                super()->start();
            }

            return record;
        }

        ~LinuxFuzzerCore() {
            for (auto &item: shadow_fd_map) {
                close(item.second);
            }

            for (auto &item: file_map) {
                unlinkat(tmp_fd, u64_to_string(item.second).data(), 0);
            }

            close(tmp_fd);
            close(null_fd);
        }
    };

    template<typename xlen>
    bool get_sync_point(
            elf::MappedFileVisitor &visitor,
            std::map<typename xlen::UXLenT, typename xlen::UXLenT> &sync_point,
            typename xlen::UXLenT shift,
            BlockVisitor::BranchMapT &block, BlockVisitor::BranchMapT &indirect
    ) {
        using UXLenT = typename xlen::UXLenT;

        auto *elf_header = elf::ELFHeader<UXLenT>::read(visitor);
        if (elf_header == nullptr) { return false; }

        std::map<UXLenT, typename elf::SymbolTableHeader<UXLenT>::SymbolTableEntry &> functions;

        for (auto &section: elf_header->sections(visitor)) {
            auto *symbol_table_header = elf::SectionHeader<UXLenT>::template
            cast<elf::SymbolTableHeader<UXLenT>>(&section, visitor);
            if (symbol_table_header == nullptr) continue;
            for (auto &symbol: symbol_table_header->get_table(visitor)) {
                switch (symbol.get_type()) {
                    case elf::SymbolTableHeader<UXLenT>::FUNCTION:
                        functions.emplace(symbol.value, symbol);
                        break;
                    default:
                        break;
                }
            }
        }

        for (auto &function: functions) {
            auto &func = function.second;
            if (func.section_header_index == 0) continue;
            auto &section = elf_header->sections(visitor)[func.section_header_index];

            void *start = visitor.address((func.value - section.address) + section.offset, func.size);
            if (start == nullptr) { return false; }

            std::vector<std::pair<UXLenT, UXLenT>> function_call{};

            auto blocks = BlockVisitor::build(func.value, start, func.size, block, indirect, function_call);

            for (auto vertex = blocks.begin(); vertex != blocks.end(); ++vertex) {
                UXLenT first = vertex.get_vertex();
                if (first == 0) continue;
            }

            std::map<UXLenT, std::set<UXLenT>> dependency;



            auto pos_dominator = PosDominatorTree<UXLenT>::build(blocks, 0);

            for (auto &item: pos_dominator) {
                UXLenT first = item.first + shift;
                UXLenT second = item.second == 0 ? 0 : item.second + shift;
                sync_point.emplace(first, second);
            }
        }

        return true;
    }

    template<typename xlen>
    bool get_dynamic_library(elf::MappedFileVisitor &visitor,
                             LinuxProgram<xlen> &pcb,
                             std::vector<std::pair<Array<char>, typename xlen::UXLenT>> &result
    ) {
        using UXLenT = typename xlen::UXLenT;

        auto *elf_header = elf::ELFHeader<UXLenT>::read(visitor);
        if (elf_header == nullptr) return false;

        auto *dynamic_header = elf_header->template
                get_section_header<elf::DynLinkingTableHeader<UXLenT>>(".dynamic", visitor);
        if (dynamic_header == nullptr) return false;

        UXLenT debug_addr = 0;

        for (auto &program: elf_header->programs(visitor)) {
            if (program.offset <= dynamic_header->offset && dynamic_header->size <= program.file_size &&
                dynamic_header->offset - program.offset <= program.file_size - dynamic_header->size) {

                usize virtual_address = program.virtual_address - program.offset + dynamic_header->offset;

                usize i = 0;
                for (auto &item: dynamic_header->get_table(visitor)) {
                    if (item.tag == elf::DynLinkingTableHeader<UXLenT>::DEBUG) { break; }
                    ++i;
                }

                debug_addr = virtual_address + dynamic_header->entry_size * i;

                break;
            }
        }

        typename elf::DynLinkingTableHeader<UXLenT>::Entry debug_entry{};
        if (!pcb.memory_copy_from_guest(&debug_entry, debug_addr, sizeof(debug_entry)))
            return false;

        DebugInfo<UXLenT> debug_info{};
        if (!pcb.memory_copy_from_guest(&debug_info, debug_entry.val, sizeof(debug_info)))
            return false;

        DebugMap<UXLenT> debug_map{};
        for (UXLenT item = debug_info.map; item != 0; item = debug_map.next) {
            if (!pcb.memory_copy_from_guest(&debug_map, item, sizeof(debug_map)))
                return false;

            Array<char> name{};
            if (!pcb.string_copy_from_guest(debug_map.name, name)) return false;

            if (debug_map.addr != 0) { result.emplace_back(std::move(name), debug_map.addr); }
        }

        return true;
    }
}


#endif //NEUTRON_RISCV_LINUX_FUZZER_HPP
