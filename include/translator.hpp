#ifndef NEUTRON_TRANSLATOR_HPP
#define NEUTRON_TRANSLATOR_HPP


#include "instruction/instruction_visitor.hpp"

#include "riscv_linux_program.hpp"
#include "emitter.hpp"


namespace neutron {

    template<typename AsT, typename XLenT>
    struct emit_touch_fn;

#define _neutron_emit_touch_fn(type, name) \
        template<typename AsT> struct emit_touch_fn<AsT, type> { \
            static constexpr auto i = &AsT::emit_t##name##_i; \
            static constexpr auto ri = &AsT::emit_t##name##_ri; \
        }

    _neutron_emit_touch_fn(i8, 8);
    _neutron_emit_touch_fn(i16, 16);
    _neutron_emit_touch_fn(i32, 32);

#undef _neutron_emit_touch_fn

    template<typename AsT, typename XLenT>
    struct emit_load_fn;

#define _neutron_emit_load_fn(type, name) \
        template<typename AsT> struct emit_load_fn<AsT, type> { \
            static constexpr auto ri = &AsT::emit_l##name##_ri; \
            static constexpr auto rri = &AsT::emit_l##name##_rri; \
        }

    _neutron_emit_load_fn(i8, 8);
    _neutron_emit_load_fn(i16, 16);
    _neutron_emit_load_fn(i32, 32);
    _neutron_emit_load_fn(u8, 8u);
    _neutron_emit_load_fn(u16, 16u);

#undef _neutron_emit_load_fn

    template<typename AsT, typename XLenT>
    struct emit_store_fn;

#define _neutron_emit_store_fn(type, name) \
        template<typename AsT> struct emit_store_fn<AsT, type> { \
            static constexpr auto ii = &AsT::emit_s##name##_ii; \
            static constexpr auto ir = &AsT::emit_s##name##_ir; \
            static constexpr auto rii = &AsT::emit_s##name##_rii; \
            static constexpr auto rir = &AsT::emit_s##name##_rir; \
        }

    _neutron_emit_store_fn(i8, 8);
    _neutron_emit_store_fn(i16, 16);
    _neutron_emit_store_fn(i32, 32);

#undef _neutron_emit_store_fn

    template<typename SubT, typename AsT, typename xlen>
    class Translator_ : public riscv_isa::InstructionVisitor<SubT, bool> {
    public:
        using SuperT = riscv_isa::InstructionVisitor<SubT, bool>;

        using RetT = typename SuperT::RetT;
        using XLenT = typename xlen::XLenT;
        using UXLenT = typename xlen::UXLenT;
        using IntRegT = riscv_isa::IntegerRegister<xlen>;

        using EmitRRIT = RetT (AsT::*)(usize, usize, XLenT);
        using EmitRRRT = RetT (AsT::*)(usize, usize, usize);
        using RIRFnT = RetT (Translator_::*)(usize, usize);

#define _neutron_int_reg_guest_ir_map(fn) \
    fn(IntRegT::RA, 0) \
    fn(IntRegT::SP, 1) \
    fn(IntRegT::T0, 2) \
    fn(IntRegT::T1, 3) \
    fn(IntRegT::S0, 4) \
    fn(IntRegT::S1, 5) \
    fn(IntRegT::A0, 6) \
    fn(IntRegT::A1, 7) \
    fn(IntRegT::A2, 8) \
    fn(IntRegT::A3, 9) \
    fn(IntRegT::A4, 10) \
    fn(IntRegT::A5, 11) \
    fn(IntRegT::A6, 12) \
    fn(IntRegT::A7, 13) \
    fn(IntRegT::T2, 14) \
    fn(IntRegT::T3, 15) \
    fn(IntRegT::T4, 16) \
    fn(IntRegT::T5, 17) \
    fn(IntRegT::T6, 18) \
    fn(IntRegT::S2, 19) \
    fn(IntRegT::S3, 20) \
    fn(IntRegT::S4, 21) \
    fn(IntRegT::S5, 22) \
    fn(IntRegT::S6, 23) \
    fn(IntRegT::S7, 24) \
    fn(IntRegT::S8, 25) \
    fn(IntRegT::S9, 26) \
    fn(IntRegT::S10, 27) \
    fn(IntRegT::S11, 28) \
    fn(IntRegT::GP, 29) \
    fn(IntRegT::TP, 30)

        static usize int_reg_guest_to_ir(usize reg) {
            switch (reg) {
#define _neutron_int_reg_guest_to_ir(guest, ir) \
                case guest: \
                    return ir;
                _neutron_int_reg_guest_ir_map(_neutron_int_reg_guest_to_ir);
#undef _neutron_int_reg_guest_to_ir
                default:
                    neutron_unreachable("unknown register number!");
            }
        }

        static usize int_reg_ir_to_guest(usize reg) {
            switch (reg) {
#define _neutron_int_reg_ir_to_guest(guest, ir) \
                case ir: \
                    return guest;
                _neutron_int_reg_guest_ir_map(_neutron_int_reg_ir_to_guest);
#undef _neutron_int_reg_ir_to_guest
                default:
                    neutron_unreachable("unknown register number!");
            }
        }

#undef _neutron_int_reg_guest_ir_map

    private:
        SubT *sub_type() { return static_cast<SubT *>(this); }

        SuperT *super() { return this; }

        LinuxProgram<xlen> &pcb;
        AsT as;
        UXLenT inst_offset;

        RetT _emit_move_rir(usize rd, usize rs2) { return as.emit_move_rr(rd, rs2); }

        RetT _emit_zero_rir(usize rd, neutron_unused usize rs2) { return as.emit_li_ri(rd, 0); }

        RetT _emit_neg_rir(usize rd, usize rs2) { return as.emit_neg_rr(rd, rs2); }

        RetT _emit_get_rir(usize rd, usize rs2) { return as.emit_sgt_rri(rd, rs2, 0); }

        RetT _emit_getu_rir(usize rd, usize rs2) { return as.emit_sgtu_rri(rd, rs2, 0); }

        template<typename ValT, typename InstT>
        RetT operate_load(const InstT *inst) {
            using SValT = typename std::make_signed<ValT>::type;

            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_imm();

            if (rd == 0) {
                if (rs1 == 0) {
                    return (as.*(emit_touch_fn<AsT, SValT>::i))(imm);
                } else {
                    return (as.*(emit_touch_fn<AsT, SValT>::ri))(int_reg_guest_to_ir(rs1), imm);
                }
            } else {
                if (rs1 == 0) {
                    return (as.*(emit_load_fn<AsT, ValT>::ri))(int_reg_guest_to_ir(rd), imm);
                } else {
                    return (as.*(emit_load_fn<AsT, ValT>::rri))(int_reg_guest_to_ir(rd),
                                                                int_reg_guest_to_ir(rs1), imm);
                }
            }
        }

        template<typename ValT, typename InstT>
        RetT operate_store(const InstT *inst) {
            usize rs1 = inst->get_rs1();
            usize rs2 = inst->get_rs2();
            XLenT imm = inst->get_imm();

            if (rs1 == 0) {
                if (rs2 == 0) {
                    return (as.*(emit_store_fn<AsT, ValT>::ii))(imm, 0);
                } else {
                    return (as.*(emit_store_fn<AsT, ValT>::ir))(imm, int_reg_guest_to_ir(rs2));
                }
            } else {
                if (rs2 == 0) {
                    return (as.*(emit_store_fn<AsT, ValT>::rii))(int_reg_guest_to_ir(rs1), imm, 0);
                } else {
                    return (as.*(emit_store_fn<AsT, ValT>::rir))(int_reg_guest_to_ir(rs1), imm,
                                                                 int_reg_guest_to_ir(rs2));
                }
            }
        }

        template<typename OP, EmitRRIT emit_fn, typename InstT>
        RetT operate_imm(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_imm();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else {
                auto ir_rd = int_reg_guest_to_ir(rd);

                if (rs1 == 0) {
                    return as.emit_li_ri(ir_rd, OP::op(0, imm));
                } else {
                    auto ir_rs1 = int_reg_guest_to_ir(rs1);

                    return (as.*emit_fn)(ir_rd, ir_rs1, imm);
                }
            }
        }

        template<typename OP, EmitRRIT emit_fn, typename InstT>
        RetT operate_imm_shift(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT imm = inst->get_shamt();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else {
                auto ir_rd = int_reg_guest_to_ir(rd);

                if (rs1 == 0) {
                    return as.emit_li_ri(ir_rd, OP::op(0, imm));
                } else {
                    auto ir_rs1 = int_reg_guest_to_ir(rs1);

                    return (as.*emit_fn)(ir_rd, ir_rs1, imm);
                }
            }
        }

        template<typename OP, EmitRRRT emit_rrr_fn, EmitRRIT emit_rri_fn, RIRFnT rir_fn, typename InstT>
        RetT operate_reg(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT rs2 = inst->get_rs2();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else {
                auto ir_rd = int_reg_guest_to_ir(rd);

                if (rs1 == 0) {
                    if (rs2 == 0) {
                        return as.emit_li_ri(ir_rd, OP::op(0, 0));
                    } else {
                        auto ir_rs2 = int_reg_guest_to_ir(rs2);

                        return (this->*rir_fn)(ir_rd, ir_rs2);
                    }
                } else {
                    auto ir_rs1 = int_reg_guest_to_ir(rs1);

                    if (rs2 == 0) {
                        return (as.*emit_rri_fn)(ir_rd, ir_rs1, 0);
                    } else {
                        auto ir_rs2 = int_reg_guest_to_ir(rs2);

                        return (as.*emit_rrr_fn)(ir_rd, ir_rs1, ir_rs2);
                    }
                }
            }
        }

    public:
        Translator_(LinuxProgram<xlen> &pcb, UXLenT inst_offset) :
                pcb{pcb}, inst_offset{inst_offset} {}

        RetT visit() {
            riscv_isa::ILenT inst_buffer = 0; // zeroing instruction buffer

#if RISCV_IALIGN == 32
            auto *ptr = pcb.template address<u32>(inst_offset, riscv_isa::EXECUTE);
            if (ptr == nullptr) { return false; }
            inst_buffer = *ptr;
#else
            auto *ptr = pcb.template address<u16>(inst_offset, riscv_isa::EXECUTE);
            if (ptr == nullptr) { return false; }
            inst_buffer = *ptr;

#if defined(__RV_EXTENSION_C__)
            if (riscv_isa::is_type<riscv_isa::Instruction16>(
                    reinterpret_cast<riscv_isa::Instruction *>(&inst_buffer)
            )) {
                return this->visit_16(reinterpret_cast<riscv_isa::Instruction16 *>(&inst_buffer));
            }
#endif // defined(__RV_EXTENSION_C__)

            ptr = pcb.template address<u16>(inst_offset + sizeof(u16), riscv_isa::EXECUTE);
            if (ptr == nullptr) { return false; }
            inst_buffer |= static_cast<u32>(*ptr) << 16u;
#endif

            if (riscv_isa::is_type<riscv_isa::Instruction32>(
                    reinterpret_cast<riscv_isa::Instruction *>(&inst_buffer)
            )) {
                return this->visit_32(reinterpret_cast<riscv_isa::Instruction32 *>(&inst_buffer));
            }

            return false;
        }

        RetT illegal_instruction(riscv_isa_unused const riscv_isa::Instruction *inst) { return false; }

        RetT visit_inst(const riscv_isa::Instruction *inst) {
            return sub_type()->illegal_instruction(inst);
        }

        RetT visit_lui_inst(const riscv_isa::LUIInst *inst) {
            usize rd = inst->get_rd();
            XLenT imm = inst->get_imm();

            inst_offset += riscv_isa::LUIInst::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else {
                return as.emit_li_ri(int_reg_guest_to_ir(rd), imm);
            }
        }

        RetT visit_auipc_inst(const riscv_isa::AUIPCInst *inst) {
            usize rd = inst->get_rd();
            XLenT imm = inst->get_imm() + inst_offset;

            inst_offset += riscv_isa::LUIInst::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else {
                return as.emit_li_ri(int_reg_guest_to_ir(rd), imm);
            }
        }

        RetT visit_jal_inst(const riscv_isa::JALInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_jalr_inst(const riscv_isa::JALRInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_beq_inst(const riscv_isa::BEQInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_bne_inst(const riscv_isa::BNEInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_blt_inst(const riscv_isa::BLTInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_bge_inst(const riscv_isa::BGEInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_bltu_inst(const riscv_isa::BLTUInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_bgeu_inst(const riscv_isa::BGEUInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_lb_inst(const riscv_isa::LBInst *inst) { return operate_load<i8>(inst); }

        RetT visit_lh_inst(const riscv_isa::LHInst *inst) { return operate_load<i16>(inst); }

        RetT visit_lw_inst(const riscv_isa::LWInst *inst) { return operate_load<i32>(inst); }

        RetT visit_lbu_inst(const riscv_isa::LBUInst *inst) { return operate_load<u8>(inst); }

        RetT visit_lhu_inst(const riscv_isa::LHUInst *inst) { return operate_load<u16>(inst); }

        RetT visit_sb_inst(const riscv_isa::SBInst *inst) { return operate_store<i8>(inst); }

        RetT visit_sh_inst(const riscv_isa::SHInst *inst) { return operate_store<i16>(inst); }

        RetT visit_sw_inst(const riscv_isa::SWInst *inst) { return operate_store<i32>(inst); }

        RetT visit_addi_inst(const riscv_isa::ADDIInst *inst) {
            return operate_imm<typename riscv_isa::operators::ADD<xlen>, &AsT::emit_add_rri>(inst);
        }

        RetT visit_slti_inst(const riscv_isa::SLTIInst *inst) {
            return operate_imm<typename riscv_isa::operators::SLT<xlen>, &AsT::emit_slt_rri>(inst);
        }

        RetT visit_sltiu_inst(const riscv_isa::SLTIUInst *inst) {
            return operate_imm<typename riscv_isa::operators::SLTU<xlen>, &AsT::emit_sltu_rri>(inst);
        }

        RetT visit_xori_inst(const riscv_isa::XORIInst *inst) {
            return operate_imm<typename riscv_isa::operators::XOR<xlen>, &AsT::emit_xor_rri>(inst);
        }

        RetT visit_ori_inst(const riscv_isa::ORIInst *inst) {
            return operate_imm<typename riscv_isa::operators::OR<xlen>, &AsT::emit_or_rri>(inst);
        }

        RetT visit_andi_inst(const riscv_isa::ANDIInst *inst) {
            return operate_imm<typename riscv_isa::operators::AND<xlen>, &AsT::emit_and_rri>(inst);
        }

        RetT visit_slli_inst(const riscv_isa::SLLIInst *inst) {
            return operate_imm_shift<typename riscv_isa::operators::SLL<xlen>, &AsT::emit_sll_rri>(inst);
        }

        RetT visit_srli_inst(const riscv_isa::SRLIInst *inst) {
            return operate_imm_shift<typename riscv_isa::operators::SRL<xlen>, &AsT::emit_srl_rri>(inst);
        }

        RetT visit_srai_inst(const riscv_isa::SRAIInst *inst) {
            return operate_imm_shift<typename riscv_isa::operators::SRA<xlen>, &AsT::emit_sra_rri>(inst);
        }

        RetT visit_add_inst(const riscv_isa::ADDInst *inst) {
            return operate_reg<typename riscv_isa::operators::ADD<xlen>,
                    &AsT::emit_add_rrr,
                    &AsT::emit_add_rri,
                    &SubT::_emit_move_rir>(inst);
        }

        RetT visit_sub_inst(const riscv_isa::SUBInst *inst) {
            return operate_reg<typename riscv_isa::operators::SUB<xlen>,
                    &AsT::emit_sub_rrr,
                    &AsT::emit_sub_rri,
                    &SubT::_emit_neg_rir>(inst);
        }

        RetT visit_sll_inst(const riscv_isa::SLLInst *inst) {
            return operate_reg<typename riscv_isa::operators::SLL<xlen>,
                    &AsT::emit_sll_rrr,
                    &AsT::emit_sll_rri,
                    &SubT::_emit_zero_rir>(inst);
        }

        RetT visit_slt_inst(const riscv_isa::SLTInst *inst) {
            return operate_reg<typename riscv_isa::operators::SLT<xlen>,
                    &AsT::emit_slt_rrr,
                    &AsT::emit_slt_rri,
                    &SubT::_emit_get_rir>(inst);
        }

        RetT visit_sltu_inst(const riscv_isa::SLTUInst *inst) {
            return operate_reg<typename riscv_isa::operators::SLTU<xlen>,
                    &AsT::emit_sltu_rrr,
                    &AsT::emit_sltu_rri,
                    &SubT::_emit_getu_rir>(inst);
        }

        RetT visit_xor_inst(const riscv_isa::XORInst *inst) {
            return operate_reg<typename riscv_isa::operators::XOR<xlen>,
                    &AsT::emit_xor_rrr,
                    &AsT::emit_xor_rri,
                    &SubT::_emit_move_rir>(inst);
        }

        RetT visit_srl_inst(const riscv_isa::SRLInst *inst) {
            return operate_reg<typename riscv_isa::operators::SRL<xlen>,
                    &AsT::emit_srl_rrr,
                    &AsT::emit_srl_rri,
                    &SubT::_emit_zero_rir>(inst);
        }

        RetT visit_sra_inst(const riscv_isa::SRAInst *inst) {
            return operate_reg<typename riscv_isa::operators::SRA<xlen>,
                    &AsT::emit_sra_rrr,
                    &AsT::emit_sra_rri,
                    &SubT::_emit_zero_rir>(inst);
        }

        RetT visit_or_inst(const riscv_isa::ORInst *inst) {
            return operate_reg<typename riscv_isa::operators::OR<xlen>,
                    &AsT::emit_or_rrr,
                    &AsT::emit_or_rri,
                    &SubT::_emit_move_rir>(inst);
        }

        RetT visit_and_inst(const riscv_isa::ANDInst *inst) {
            return operate_reg<typename riscv_isa::operators::AND<xlen>,
                    &AsT::emit_and_rrr,
                    &AsT::emit_and_rri,
                    &SubT::_emit_zero_rir>(inst);
        }

#if defined(__RV_EXTENSION_M__)

        template<EmitRRRT emit_fn, typename InstT>
        RetT operate_multiply(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT rs2 = inst->get_rs2();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else if (rs1 == 0 || rs2 == 0) {
                return as.emit_li_ri(rd, 0);
            } else {
                return (as.*emit_fn)(rd, rs1, rs2);
            }
        }

        template<EmitRRRT emit_fn, typename InstT>
        RetT operate_divide(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT rs2 = inst->get_rs2();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else if (rs2 == 0) {
                return as.emit_li_ri(rd, -1);
            } else if (rs1 == 0) {
                return as.emit_li_ri(rd, 0);
            } else {
                return (as.*emit_fn)(rd, rs1, rs2);
            }
        }

        template<EmitRRRT emit_fn, typename InstT>
        RetT operate_remain(const InstT *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            XLenT rs2 = inst->get_rs2();

            inst_offset += InstT::INST_WIDTH;

            if (rd == 0) {
                return as.emit_nop();
            } else if (rs1 == 0) {
                return as.emit_li_ri(rd, 0);
            } else if (rs2 == 0) {
                return as.emit_move_rr(rd, rs1);
            } else {
                return (as.*emit_fn)(rd, rs1, rs2);
            }
        }

        RetT visit_mul_inst(const riscv_isa::MULInst *inst) {
            return operate_multiply<&AsT::emit_mul_rrr>(inst);
        }

        RetT visit_mulh_inst(const riscv_isa::MULHInst *inst) {
            return operate_multiply<&AsT::emit_mulh_rrr>(inst);
        }

        RetT visit_mulhsu_inst(const riscv_isa::MULHSUInst *inst) {
            return operate_multiply<&AsT::emit_mulhsu_rrr>(inst);
        }

        RetT visit_mulhu_inst(const riscv_isa::MULHUInst *inst) {
            return operate_multiply<&AsT::emit_mulhu_rrr>(inst);
        }

        RetT visit_div_inst(const riscv_isa::DIVInst *inst) {
            return operate_divide<&AsT::emit_div_rrr>(inst);
        }

        RetT visit_divu_inst(const riscv_isa::DIVUInst *inst) {
            return operate_divide<&AsT::emit_divu_rrr>(inst);
        }

        RetT visit_rem_inst(const riscv_isa::REMInst *inst) {
            return operate_remain<&AsT::emit_rem_rrr>(inst);
        }

        RetT visit_remu_inst(const riscv_isa::REMUInst *inst) {
            return operate_remain<&AsT::emit_remu_rrr>(inst);
        }

#endif // defined(__RV_EXTENSION_M__)
#if defined(__RV_EXTENSION_A__)

        RetT visit_lrw_inst(const riscv_isa::LRWInst *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();

            if (rd == 0) {
                if (rs1 == 0) {
                    return as.emit_t32r_i(0);
                } else {
                    return as.emit_t32r_r(int_reg_guest_to_ir(rs1));
                }
            } else {
                if (rs1 == 0) {
                    return as.emit_l32r_ri(int_reg_guest_to_ir(rd), 0);
                } else {
                    return as.emit_l32r_rr(int_reg_guest_to_ir(rd), int_reg_guest_to_ir(rs1));
                }
            }
        }

        RetT visit_scw_inst(const riscv_isa::SCWInst *inst) {
            usize rd = inst->get_rd();
            usize rs1 = inst->get_rs1();
            usize rs2 = inst->get_rs2();

            if (rd == 0) {
                return as.emit_nop();
            } else {
                if (rs1 == 0) {
                    if (rs2 == 0) {
                        return as.emit_s32c_rii(int_reg_guest_to_ir(rd), 0, 0);
                    } else {
                        return as.emit_s32c_rir(int_reg_guest_to_ir(rd), 0, int_reg_guest_to_ir(rs2));
                    }
                } else {
                    if (rs2 == 0) {
                        return as.emit_s32c_rri(int_reg_guest_to_ir(rd), int_reg_guest_to_ir(rs1), 0);
                    } else {
                        return as.emit_s32c_rrr(int_reg_guest_to_ir(rd),
                                                int_reg_guest_to_ir(rs1),
                                                int_reg_guest_to_ir(rs2));
                    }
                }
            }
        }

        RetT visit_amoswapw_inst(const riscv_isa::AMOSWAPWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amoaddw_inst(const riscv_isa::AMOADDWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amoxorw_inst(const riscv_isa::AMOXORWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amoandw_inst(const riscv_isa::AMOANDWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amoorw_inst(const riscv_isa::AMOORWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amominw_inst(const riscv_isa::AMOMINWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amomaxw_inst(const riscv_isa::AMOMAXWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amominuw_inst(const riscv_isa::AMOMINUWInst *inst) { return sub_type()->visit_inst(inst); }

        RetT visit_amomaxuw_inst(const riscv_isa::AMOMAXUWInst *inst) { return sub_type()->visit_inst(inst); }

#endif // defined(__RV_EXTENSION_A__)
    };

    template<typename AST, typename xlen>
    class Translator : public Translator_<Translator<AST, xlen>, AST, xlen> {
    public:
        Translator(LinuxProgram<xlen> &pcb, typename xlen::UXLenT inst_offset) :
                Translator_<Translator<AST, xlen>, AST, xlen>{pcb, inst_offset} {}
    };
}


#endif //NEUTRON_TRANSLATOR_HPP
