#ifndef NEUTRON_RISCV_LINUX_FUZZER_HPP
#define NEUTRON_RISCV_LINUX_FUZZER_HPP


#include <iostream>
#include <vector>

#include "target/hart.hpp"
#include "target/dump.hpp"

using namespace riscv_isa;

#include "riscv_linux_program.hpp"
#include "riscv_linux.hpp"
#include "unix_std.hpp"


namespace neutron {
    struct BranchRecord {
    public:
        using UXLenT = xlen_trait::UXLenT;

        enum {
            BEQ, BNE, BLT, BGE, BLTU, BGEU, JAL, JALR,
        } type;

        UXLenT address;

        union {
            struct {
                UXLenT op1, op2;
            } branch;
            struct {
                u8 link;
            } jal;
            struct {
                UXLenT target;
                u8 link;
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

        static BranchRecord jalr(UXLenT address, UXLenT target, u8 link) {
            return BranchRecord{JALR, address, {.jalr = {target, link}}};
        }

        UXLenT get_op1() { return inner.branch.op1; }

        UXLenT get_op2() { return inner.branch.op2; }

        UXLenT get_target() { return inner.jalr.target; }
    };

    struct ExecuteRecord {
        std::vector<u8> input;
        std::vector<BranchRecord> branch;
    };

    class LinuxRecordHart : public LinuxHart<LinuxRecordHart> {
    private:
        LinuxHart<LinuxRecordHart> *super() { return this; }

    protected:
        ExecuteRecord execute_record;
        i32 input_offset;

    public:
        LinuxRecordHart(UXLenT hart_id, LinuxProgram<> &mem) :
                LinuxHart<LinuxRecordHart>{hart_id, mem}, input_offset{0} {}

        RetT visit_jal_inst(JALInst *inst) {
            execute_record.branch.emplace_back(BranchRecord::jal(get_pc(), inst->get_rd()));

            return super()->visit_jal_inst(inst);
        }

        RetT visit_jalr_inst(JALRInst *inst) {
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_imm();
            UXLenT target = get_bits<UXLenT, XLEN, 1, 1>(int_reg.get_x(rs1) + imm);

            execute_record.branch.emplace_back(BranchRecord::jalr(get_pc(), target, inst->get_rd()));

            return super()->visit_jalr_inst(inst);
        }

        RetT visit_beq_inst(BEQInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::beq(get_pc(), op1, op2));

            return super()->visit_beq_inst(inst);
        }

        RetT visit_bne_inst(BNEInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::bne(get_pc(), op1, op2));

            return super()->visit_bne_inst(inst);
        }

        RetT visit_blt_inst(BLTInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::blt(get_pc(), op1, op2));

            return super()->visit_blt_inst(inst);
        }

        RetT visit_bge_inst(BGEInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::bge(get_pc(), op1, op2));

            return super()->visit_bge_inst(inst);
        }

        RetT visit_bltu_inst(BLTUInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::bltu(get_pc(), op1, op2));

            return super()->visit_bltu_inst(inst);
        }

        RetT visit_bgeu_inst(BGEUInst *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            execute_record.branch.emplace_back(BranchRecord::bgeu(get_pc(), op1, op2));

            return super()->visit_bgeu_inst(inst);
        }

        XLenT sys_lseek(XLenT fd, XLenT offset, XLenT whence) {
            if (fd == 0) {
                i32 new_input_offset;

                switch (whence) {
                    case SEEK_SET:
                        new_input_offset = offset;
                        break;
                    case SEEK_CUR:
                        if (input_offset > INT32_MAX - offset) return -EOVERFLOW;
                        new_input_offset = input_offset + offset;
                        break;
                    case SEEK_END:
                        riscv_isa_abort("seek end not implemented!");
                    case SEEK_HOLE:
                        riscv_isa_abort("seek hole not implemented!");
                    case SEEK_DATA:
                        riscv_isa_abort("seek data not implemented!");
                    default:
                        riscv_isa_abort("unknown seek type!");
                }

                if (new_input_offset < 0) return -EINVAL;

                for (int i = execute_record.input.size(); i < new_input_offset; ++i)
                    execute_record.input.emplace_back(rand());

                input_offset = new_input_offset;
                return input_offset;
            } else {
                return lseek(fd, offset, whence);
            }
        }

        XLenT sys_read(XLenT fd, UXLenT addr, XLenT size) {
            if (input_offset > INT32_MAX - size) return -EOVERFLOW;

            char *buffer = new char[size];

            XLenT result;
            if (fd == 0) {
                i32 i = 0, j = input_offset;

                for (; i < size && static_cast<u64>(j) < execute_record.input.size(); ++i, ++j) {
                    buffer[i] = execute_record.input[j];
                }

                for (; i < size; ++i) {
                    buffer[i] = rand();
                    execute_record.input.emplace_back(buffer[i]);
                }

                input_offset += size;

                result = size;
            } else {
                result = read(fd, buffer, size);
            }

            for (i32 i = 0; i < size; ++i) {
                char *byte = pcb.address_write<char>(addr + i); // todo: optimize
                if (byte == nullptr) return 0;
                else *byte = buffer[i];
            }

            delete[] buffer;

            return result;
        }

        ExecuteRecord start() {
            while (visit() || supervisor_trap_handler(csr_reg[CSRRegT::SCAUSE]));

            return execute_record;
        }
    };

    class LinuxCompareHart : public LinuxHart<LinuxCompareHart> {
    private:
        LinuxHart<LinuxCompareHart> *super() { return this; }

    protected:
        const ExecuteRecord &record;
        std::vector<BranchRecord>::iterator iter;
        std::vector<UXLenT> stack, cmp_stack;
        i32 input_offset;
        usize offset;
        u8 new_value;
        bool sync;

        static bool is_link(usize reg) { return reg == 1 || reg == 5; }

    public:
        LinuxCompareHart(UXLenT hart_id, LinuxProgram<> &mem, ExecuteRecord &record, usize offset, u8 new_value) :
                LinuxHart<LinuxCompareHart>{hart_id, mem}, record{record}, iter{record.branch.begin()},
                input_offset{0}, offset{offset}, new_value{new_value}, sync{true} {}

        RetT visit_jal_inst(JALInst *inst) {
            usize rd = inst->get_rd();

            if (is_link(rd)) stack.emplace_back(get_pc() + JALInst::INST_WIDTH);

            if (sync) {
                if (iter == record.branch.end()) riscv_isa_abort("");
                if (iter->address != static_cast<UXLenT>(get_pc())) riscv_isa_abort("");

                if (is_link(rd)) cmp_stack.emplace_back(get_pc() + JALInst::INST_WIDTH);

                ++iter;
            } else {

            }

            return super()->visit_jal_inst(inst);
        }

        RetT visit_jalr_inst(JALRInst *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_imm();
            UXLenT target = get_bits<UXLenT, XLEN, 1, 1>(int_reg.get_x(rs1) + imm);

            if (is_link(rd)) {
                if (is_link(rs1) && rd != rs1) stack.pop_back();
                stack.emplace_back(get_pc() + JALRInst::INST_WIDTH);
            } else {
                if (is_link(rs1)) {
                    if (target != stack.back()) riscv_isa_abort("");
                    stack.pop_back();
                }
            }

            if (sync) {
                if (iter == record.branch.end()) riscv_isa_abort("");
                if (iter->address != static_cast<UXLenT>(get_pc())) riscv_isa_abort("");

                if (is_link(rd)) {
                    if (is_link(rs1) && rd != rs1) cmp_stack.pop_back();
                    cmp_stack.emplace_back(get_pc() + JALRInst::INST_WIDTH);
                } else {
                    if (is_link(rs1)) {
                        if (target != cmp_stack.back()) riscv_isa_abort("");
                        cmp_stack.pop_back();
                    }
                }

                if (iter->get_target() != target) {
                    std::cout << std::hex << get_pc() << std::dec << std::endl;
                    sync = false;
                }

                ++iter;
            } else {

            }

            return super()->visit_jalr_inst(inst);
        }

        template<typename OP, typename InstT>
        RetT operate_branch_compare(InstT *inst) {
            UXLenT op1 = int_reg.get_x(inst->get_rs1());
            UXLenT op2 = int_reg.get_x(inst->get_rs2());

            if (sync) {
                if (iter == record.branch.end()) riscv_isa_abort("");
                if (iter->address != static_cast<UXLenT>(get_pc())) riscv_isa_abort("");

                if (iter->get_op1() != op1 || iter->get_op2() != op2)
                    std::cout << std::hex << get_pc() << std::dec << std::endl;

                if (OP::op(iter->get_op1(), iter->get_op2()) != OP::op(op1, op2))
                    sync = false;

                ++iter;
            } else {

            }

            return operate_branch<OP>(inst);
        }

        RetT visit_beq_inst(BEQInst *inst) {
            return operate_branch_compare<typename operators::EQ<xlen_trait>>(inst);
        }

        RetT visit_bne_inst(BNEInst *inst) {
            return operate_branch_compare<typename operators::NE<xlen_trait>>(inst);
        }

        RetT visit_blt_inst(BLTInst *inst) {
            return operate_branch_compare<typename operators::LT<xlen_trait>>(inst);
        }

        RetT visit_bge_inst(BGEInst *inst) {
            return operate_branch_compare<typename operators::GE<xlen_trait>>(inst);
        }

        RetT visit_bltu_inst(BLTUInst *inst) {
            return operate_branch_compare<typename operators::LTU<xlen_trait>>(inst);
        }

        RetT visit_bgeu_inst(BGEUInst *inst) {
            return operate_branch_compare<typename operators::GEU<xlen_trait>>(inst);
        }

        XLenT sys_lseek(XLenT fd, XLenT offset, XLenT whence) {
            if (fd == 0) {
                i32 new_input_offset;

                switch (whence) {
                    case SEEK_SET:
                        new_input_offset = offset;
                        break;
                    case SEEK_CUR:
                        if (input_offset > INT32_MAX - offset) return -EOVERFLOW;
                        new_input_offset = input_offset + offset;
                        break;
                    case SEEK_END:
                        riscv_isa_abort("seek end not implemented!");
                    case SEEK_HOLE:
                        riscv_isa_abort("seek hole not implemented!");
                    case SEEK_DATA:
                        riscv_isa_abort("seek data not implemented!");
                    default:
                        riscv_isa_abort("unknown seek type!");
                }

                if (new_input_offset < 0) return -EINVAL;

//                for (int i = record.input.size(); i < new_input_offset; ++i)
//                    record.input.emplace_back(rand());

                input_offset = new_input_offset;
                return input_offset;
            } else {
                return lseek(fd, offset, whence);
            }
        }

        XLenT sys_read(XLenT fd, UXLenT addr, XLenT size) {
            if (input_offset > INT32_MAX - size) return -EOVERFLOW;

            char *buffer = new char[size];

            XLenT result;
            if (fd == 0) {
                i32 i = 0, j = input_offset;

                for (; i < size; ++i, ++j) {
                    buffer[i] = static_cast<usize>(j) == offset ? new_value : record.input[j];
                }

//                for (; i < size; ++i) {
//                    buffer[i] = rand();
//                    record.input.emplace_back(buffer[i]);
//                }

                input_offset += size;

                result = size;
            } else {
                result = read(fd, buffer, size);
            }

            for (i32 i = 0; i < size; ++i) {
                char *byte = pcb.address_write<char>(addr + i); // todo: optimize
                if (byte == nullptr) return 0;
                else *byte = buffer[i];
            }

            delete[] buffer;

            return result;
        }

        void start() {
            while (visit() || supervisor_trap_handler(csr_reg[CSRRegT::SCAUSE]));
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_FUZZER_HPP
