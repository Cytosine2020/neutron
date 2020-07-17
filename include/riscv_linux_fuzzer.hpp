#ifndef NEUTRON_RISCV_LINUX_FUZZER_HPP
#define NEUTRON_RISCV_LINUX_FUZZER_HPP


#include <iostream>
#include <vector>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "neutron_utility.hpp"
#include "riscv_linux_program.hpp"
#include "riscv_linux.hpp"
#include "unix_std.hpp"


namespace neutron {
    struct BranchRecord {
    public:
        using UXLenT = riscv_isa::xlen_trait::UXLenT;

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

        UXLenT get_op1() { return inner.branch.op1; }

        UXLenT get_op2() { return inner.branch.op2; }

        UXLenT get_target() { return inner.jalr.target; }

        u8 get_jal_rd() { return inner.jal.rd; }

        u8 get_jalr_rd() { return inner.jalr.rd; }

        u8 get_jalr_rs1() { return inner.jalr.rs1; }
    };

    class LinuxFuzzerHart : public LinuxHart<LinuxFuzzerHart> {
    private:
        using SuperT = LinuxHart<LinuxFuzzerHart>;

        SuperT *super() { return this; }

    protected:
        std::vector<BranchRecord> record;
        std::vector<u8> &input;
        usize input_offset;

    public:
        LinuxFuzzerHart(UXLenT hart_id, LinuxProgram<> &mem, std::vector<u8> &input) :
                LinuxHart<LinuxFuzzerHart>{hart_id, mem}, record{}, input{input}, input_offset{0} {}

        RetT visit_jal_inst(riscv_isa::JALInst *inst) {
            record.emplace_back(BranchRecord::jal(get_pc(), inst->get_rd()));

            return super()->visit_jal_inst(inst);
        }

        RetT visit_jalr_inst(riscv_isa::JALRInst *inst) {
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_imm();
            UXLenT target = get_bits<UXLenT, XLEN, 1, 1>(get_x(rs1) + imm);

            record.emplace_back(BranchRecord::jalr(get_pc(), target, inst->get_rd(), rs1));

            return super()->visit_jalr_inst(inst);
        }

        RetT visit_beq_inst(riscv_isa::BEQInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::beq(get_pc(), op1, op2));

            return super()->visit_beq_inst(inst);
        }

        RetT visit_bne_inst(riscv_isa::BNEInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::bne(get_pc(), op1, op2));

            return super()->visit_bne_inst(inst);
        }

        RetT visit_blt_inst(riscv_isa::BLTInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::blt(get_pc(), op1, op2));

            return super()->visit_blt_inst(inst);
        }

        RetT visit_bge_inst(riscv_isa::BGEInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::bge(get_pc(), op1, op2));

            return super()->visit_bge_inst(inst);
        }

        RetT visit_bltu_inst(riscv_isa::BLTUInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::bltu(get_pc(), op1, op2));

            return super()->visit_bltu_inst(inst);
        }

        RetT visit_bgeu_inst(riscv_isa::BGEUInst *inst) {
            UXLenT op1 = get_x(inst->get_rs1());
            UXLenT op2 = get_x(inst->get_rs2());

            record.emplace_back(BranchRecord::bgeu(get_pc(), op1, op2));

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
                        if (input_offset > static_cast<usize>(INT32_MAX - offset)) return -EOVERFLOW;
                        new_input_offset = input_offset + offset;
                        break;
                    case SEEK_END:
                        neutron_abort("seek end not implemented!");
                    case SEEK_HOLE:
                        neutron_abort("seek hole not implemented!");
                    case SEEK_DATA:
                        neutron_abort("seek data not implemented!");
                    default:
                        neutron_abort("unknown seek type!");
                }

                if (new_input_offset < 0) return -EINVAL;

                for (int i = input.size(); i < new_input_offset; ++i)
                    input.emplace_back(rand());

                input_offset = new_input_offset;
                return input_offset;
            } else {
                return lseek(fd, offset, whence);
            }
        }

        XLenT sys_read(XLenT fd, UXLenT addr, XLenT size) {
            if (input_offset > static_cast<usize>(INT32_MAX - size)) return -EOVERFLOW;

            char *buffer = new char[size];

            XLenT result;
            if (fd == 0) {
                i32 i = 0, j = input_offset;

                for (; i < size && static_cast<u64>(j) < input.size(); ++i, ++j) {
                    buffer[i] = input[j];
                }

                for (; i < size; ++i) {
                    buffer[i] = rand();
                    input.emplace_back(buffer[i]);
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

        std::vector<BranchRecord> start() {
            super()->start();

            return record;
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_FUZZER_HPP
