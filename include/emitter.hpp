#ifndef NEUTRON_EMITTER_HPP
#define NEUTRON_EMITTER_HPP


#include <asmjit/x86.h>

#include "neutron_utility.hpp"
#include "dynamic_translation.h"


namespace neutron {
    template<typename xlen>
    class Emitter {
    public:
        using RetT = bool;
        using XLenT = typename xlen::XLenT;
        using UXLenT = typename xlen::UXLenT;

        using AsT = asmjit::x86::Assembler;
        using AsBaseT = asmjit::x86::EmitterExplicitT<AsT>;

        using EmitRT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Gp &);
        using EmitMT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Mem &);
        using EmitRRT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Gp &, const asmjit::x86::Gp &);
        using EmitRMT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Gp &, const asmjit::x86::Mem &);
        using EmitMRT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Mem &, const asmjit::x86::Gp &);
        using EmitRIT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Gp &, const asmjit::Imm &);
        using EmitMIT = asmjit::Error (AsBaseT::*)(const asmjit::x86::Mem &, const asmjit::Imm &);

    private:
        static usize int_reg_is_host_reg(usize reg) { return reg < 12; }

        static asmjit::x86::Gp int_reg_ir_to_host(usize reg) {
            switch (reg) {
                case 0:
                    return asmjit::x86::edx;
                case 1:
                    return asmjit::x86::ebx;
                case 2:
                    return asmjit::x86::esi;
                case 3:
                    return asmjit::x86::edi;
                case 4:
                    return asmjit::x86::r8d;
                case 5:
                    return asmjit::x86::r9d;
                case 6:
                    return asmjit::x86::r10d;
                case 7:
                    return asmjit::x86::r11d;
                case 8:
                    return asmjit::x86::r12d;
                case 9:
                    return asmjit::x86::r13d;
                case 10:
                    return asmjit::x86::r14d;
                case 11:
                    return asmjit::x86::r15d;
                default:
                    neutron_unreachable("unknown register!");
            }
        }

        static asmjit::x86::Mem int_reg_ir_to_mem(usize reg) {
            usize offset = offsetof(struct dynamic_info, int_reg[reg]);
            return asmjit::x86::ptr_32(asmjit::x86::rbp, offset);
        }

        static const asmjit::x86::Gp INTER_REG;

        AsT as;

        template<EmitRT op_r_fn, EmitMT op_m_fn>
        RetT emit_x86_x(usize rd) {
            if (int_reg_is_host_reg(rd)) {
                return !(as.*op_r_fn)(int_reg_ir_to_host(rd));
            } else {
                return !(as.*op_m_fn)(int_reg_ir_to_mem(rd));
            }
        }

#define emit_x86_x(op, rd) emit_x86_x<&AsT::op, &AsT::op>(rd)

        template<EmitRRT op_rr_fn, EmitRMT op_rm_fn>
        RetT emit_x86_rx(const asmjit::x86::Gp &host_rd, usize rs) {
            if (int_reg_is_host_reg(rs)) {
                return !(as.*op_rr_fn)(host_rd, int_reg_ir_to_host(rs));
            } else {
                return !(as.*op_rm_fn)(host_rd, int_reg_ir_to_mem(rs));
            }
        }

#define emit_x86_rx(op, rd, rs) emit_x86_rx<&AsT::op, &AsT::op>(rd, rs)

        template<EmitRRT op_rr_fn, EmitMRT op_mr_fn>
        RetT emit_x86_xr(usize rd, const asmjit::x86::Gp &host_rs) {
            if (int_reg_is_host_reg(rd)) {
                return !(as.*op_rr_fn)(int_reg_ir_to_host(rd), host_rs);
            } else {
                return !(as.*op_mr_fn)(int_reg_ir_to_mem(rd), host_rs);
            }
        }

#define emit_x86_xr(op, rd, rs) emit_x86_xr<&AsT::op, &AsT::op>(rd, rs)

        template<EmitRRT op_rr_fn, EmitRMT op_rm_fn, EmitMRT op_mr_fn>
        RetT emit_x86_xx(usize rd, usize rs) {
            if (int_reg_is_host_reg(rd)) {
                return emit_x86_rx<op_rr_fn, op_rm_fn>(int_reg_ir_to_host(rd), rs);
            } else {
                auto mem_rd = int_reg_ir_to_mem(rd);

                if (int_reg_is_host_reg(rs)) {
                    return !(as.*op_mr_fn)(mem_rd, int_reg_ir_to_host(rs));
                } else {
                    return !as.mov(INTER_REG, int_reg_ir_to_mem(rs)) &&
                           !(as.*op_mr_fn)(mem_rd, INTER_REG);
                }
            }
        }

#define emit_x86_xx(op, rd, rs) emit_x86_xx<&AsT::op, &AsT::op, &AsT::op>(rd, rs)

        RetT emit_x86_move_zero_xb(usize rd, const asmjit::x86::Gp &rs) {
            if (int_reg_is_host_reg(rd)) {
                return !as.movzx(int_reg_ir_to_host(rd), rs);
            } else {
                return !as.movzx(INTER_REG, rs) &&
                       !as.mov(int_reg_ir_to_mem(rd), INTER_REG);
            }
        }

        RetT move_reg_to_inter(usize reg) { return emit_x86_rx(mov, INTER_REG, reg); }

        RetT move_inter_to_reg(usize reg) { return emit_x86_xr(mov, reg, INTER_REG); }

        RetT emit_address(usize size, usize offset, void *mmu_fn) {
            auto start = asmjit::x86::ptr_32(asmjit::x86::rbp, offset + offsetof(struct memory_area, start));
            auto end = asmjit::x86::ptr_32(asmjit::x86::rbp, offset + offsetof(struct memory_area, end));

            auto cache_miss = as.newLabel();
            auto cache_hit = as.newLabel();
            auto trap = as.newLabel();

            // todo: handle host trap

            return (size > 8 || !as.test(INTER_REG, size / 8 - 1)) &&
                   !as.jnz(trap) &&
                   !as.cmp(INTER_REG, start) &&
                   !as.jb(cache_miss) &&
                   !as.cmp(INTER_REG, end) &&
                   !as.jb(cache_hit) &&
                   !as.bind(cache_miss) &&

                   !as.mov(asmjit::x86::rax, reinterpret_cast<usize>(&mmu_fn)) &&
                   !as.call(reinterpret_cast<usize>(&neutron_dynamic_fast_call)) &&

                   !as.test(asmjit::x86::rax, asmjit::x86::rax) && // return 0 means page fault
                   !as.jnz(cache_hit) &&
                   !as.bind(trap) &&
                   !as.ret() &&
                   !as.bind(cache_hit);
        }

        RetT emit_touch_address(usize size) {
            return emit_address(size, offsetof(struct dynamic_info, load_cache),
                                reinterpret_cast<void *>(&neutron_mmu_load));
        }

        RetT emit_load_address(usize size) {
            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, load_cache.shift));

            return emit_address(size, offsetof(struct dynamic_info, load_cache),
                                reinterpret_cast<void *>(&neutron_mmu_load)) &&
                   !as.add(INTER_REG.r64(), shift);
        }

        RetT emit_store_address(usize size) {
            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, store_cache.shift));

            return emit_address(size, offsetof(struct dynamic_info, store_cache),
                                reinterpret_cast<void *>(&neutron_mmu_store)) &&
                   !as.add(INTER_REG.r64(), shift);
        }

        RetT emit_load_reserve_address(usize size) {
            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, load_cache.shift));
            auto r_addr = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_address));
            auto r_val = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_value));
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            return emit_address(size, offsetof(struct dynamic_info, load_cache),
                                reinterpret_cast<void *>(&neutron_mmu_load)) &&
                   !as.mov(r_addr, INTER_REG) &&
                   !as.add(INTER_REG.r64(), shift) &&
                   !as.movsx(asmjit::x86::rax, ptr) &&
                   !as.mov(r_val, asmjit::x86::rax);
        }

        RetT emit_store_conditional_address(usize size) {
            (void) size;

            return false; // todo
        }

        template<usize size>
        RetT emit_touch_i(UXLenT addr) {
            return (addr == 0 ? !as.xor_(INTER_REG, INTER_REG)
                              : !as.mov(INTER_REG, addr)) &&
                   emit_touch_address(size);
        }

        template<usize size>
        RetT emit_touch_ri(usize rs1, UXLenT addr) {
            return emit_x86_rx(mov, INTER_REG, rs1) &&
                   (addr == 0 || !as.add(INTER_REG, addr)) &&
                   emit_touch_address(size);
        }

        template<usize size>
        RetT emit_load_ri(usize rd, UXLenT addr) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (addr == 0 ? as.xor_(INTER_REG, INTER_REG) : as.mov(INTER_REG, addr)) { return false; }
            if (!emit_load_address(size)) { return false; }

            if (int_reg_is_host_reg(rd)) {
                return !as.movsx(int_reg_ir_to_host(rd), ptr);
            } else {
                return !as.movsx(asmjit::x86::eax, ptr) &&
                       as.mov(int_reg_ir_to_mem(rd), asmjit::x86::eax);
            }
        }

        template<usize size>
        RetT emit_load_rri(usize rd, usize rs1, UXLenT addr) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (!emit_x86_rx(mov, INTER_REG, rs1)) { return false; }
            if (addr != 0 && as.add(INTER_REG, addr)) { return false; }
            if (!emit_load_address(size)) { return false; }

            if (int_reg_is_host_reg(rd)) {
                return !as.movsx(int_reg_ir_to_host(rd), ptr);
            } else {
                return !as.movsx(asmjit::x86::eax, ptr) &&
                       as.mov(int_reg_ir_to_mem(rd), asmjit::x86::eax);
            }
        }

        template<usize size>
        RetT emit_load_u_ri(usize rd, UXLenT addr) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (addr == 0 ? as.xor_(INTER_REG, INTER_REG) : as.mov(INTER_REG, addr)) { return false; }
            if (!emit_load_address(size)) { return false; }

            if (int_reg_is_host_reg(rd)) {
                return !as.movzx(int_reg_ir_to_host(rd), ptr);
            } else {
                return !as.movzx(asmjit::x86::eax, ptr) &&
                       as.mov(int_reg_ir_to_mem(rd), asmjit::x86::eax);
            }
        }

        template<usize size>
        RetT emit_load_u_rri(usize rd, usize rs1, UXLenT addr) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (!emit_x86_rx(mov, INTER_REG, rs1)) { return false; }
            if (addr != 0 && as.add(INTER_REG, addr)) { return false; }
            if (!emit_load_address(size)) { return false; }

            if (int_reg_is_host_reg(rd)) {
                return !as.movzx(int_reg_ir_to_host(rd), ptr);
            } else {
                return !as.movzx(asmjit::x86::eax, ptr) &&
                       as.mov(int_reg_ir_to_mem(rd), asmjit::x86::eax);
            }
        }

        template<usize size>
        RetT emit_store_ii(UXLenT addr, XLenT src) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            return (addr == 0 ? !as.xor_(INTER_REG, INTER_REG)
                              : !as.mov(INTER_REG, addr)) &&
                   emit_store_address(size) &&
                   !as.mov(ptr, src);
        }

        template<usize size>
        RetT emit_store_ir(UXLenT addr, usize rs2) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (addr == 0 ? as.xor_(INTER_REG, INTER_REG) : as.mov(INTER_REG.r64(), addr)) { return false; }
            if (!emit_store_address(size)) { return false; }

            if (int_reg_is_host_reg(rs2)) {
                return !as.mov(ptr, int_reg_ir_to_host(rs2));
            } else {
                return !as.mov(asmjit::x86::eax, int_reg_ir_to_mem(rs2)) &&
                       !as.mov(ptr, asmjit::x86::eax);
            }
        }

        template<usize size>
        RetT emit_store_rii(usize rs1, UXLenT base, XLenT src) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            return emit_x86_rx(mov, INTER_REG, rs1) &&
                   (base == 0 || !as.add(INTER_REG, base)) &&
                   emit_store_address(size) &&
                   !as.mov(ptr, src);
        }

        template<usize size>
        RetT emit_store_rir(usize rs1, UXLenT base, usize rs2) {
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, size);

            if (!emit_x86_rx(mov, INTER_REG, rs1)) return false;
            if (base == 0 || as.add(INTER_REG, base)) { return false; }
            if (!emit_store_address(size)) { return false; }

            if (int_reg_is_host_reg(rs2)) {
                return !as.mov(ptr, int_reg_ir_to_host(rs2));
            } else {
                return !as.mov(asmjit::x86::eax, int_reg_ir_to_mem(rs2)) &&
                       !as.mov(ptr, asmjit::x86::eax);
            }
        }

        template<EmitRT op_r_fn, EmitMT op_m_fn>
        RetT emit_inst_rr(usize rd, usize rs1) {
            if (rd == rs1) {
                return emit_x86_x<op_r_fn, op_m_fn>(rd);
            } else {
                return move_reg_to_inter(rs1) &&
                       !(as.*op_r_fn)(INTER_REG) &&
                       move_inter_to_reg(rd);
            }
        }

#define emit_inst_rr(op, rd, rs1) emit_inst_rr<&AsT::op, &AsT::op>(rd, rs1)

        template<EmitRIT op_ri_fn, EmitMIT op_mi_fn>
        RetT emit_inst_rri(usize rd, usize rs1, XLenT imm_) {
            asmjit::Imm imm{imm_};

            if (rd == rs1) {
                if (int_reg_is_host_reg(rd)) {
                    return !(as.*op_ri_fn)(int_reg_ir_to_host(rd), imm);
                } else {
                    return !(as.*op_mi_fn)(int_reg_ir_to_mem(rd), imm);
                }
            } else {
                return move_reg_to_inter(rs1) &&
                       !(as.*op_ri_fn)(INTER_REG, imm) &&
                       move_inter_to_reg(rd);
            }
        }

#define emit_inst_rri(op, rd, rs1, imm) emit_inst_rri<&AsT::op, &AsT::op>(rd, rs1, imm)

        template<EmitRT op_r_fn>
        RetT emit_cmp_set_rri(usize rd, usize rs1, XLenT imm) {
            auto inter = asmjit::x86::cl;

            return emit_cmp_ri(rs1, imm) &&
                   !(as.*op_r_fn)(inter) &&
                   emit_x86_move_zero_xb(rd, inter);
        }

#define emit_cmp_set_rri(op, rd, rs1, imm) emit_cmp_set_rri<&AsT::op>(rd, rs1, imm)

        template<EmitRRT op_rr_fn, EmitRMT op_rm_fn, EmitMRT op_mr_fn>
        RetT emit_inst_rrr(usize rd, usize rs1, usize rs2) {
            if (rd == rs1) {
                return emit_x86_xx<op_rr_fn, op_rm_fn, op_mr_fn>(rd, rs2);
            } else {
                return move_reg_to_inter(rs1) &&
                       emit_x86_rx<op_rr_fn, op_rm_fn>(INTER_REG, rs2) &&
                       move_inter_to_reg(rd);
            }
        }

#define emit_inst_rrr(op, rd, rs1, rs2) emit_inst_rrr<&AsT::op, &AsT::op, &AsT::op>(rd, rs1, rs2)

        template<EmitRRT op_rr_fn, EmitRMT op_rm_fn, EmitMRT op_mr_fn>
        RetT emit_commutative_rrr(usize rd, usize rs1, usize rs2) {
            if (rd == rs1) {
                return emit_x86_xx<op_rr_fn, op_rm_fn, op_mr_fn>(rd, rs2);
            } else if (rd == rs2) {
                return emit_x86_xx<op_rr_fn, op_rm_fn, op_mr_fn>(rd, rs1);
            } else if (int_reg_is_host_reg(rs2)) {
                return !as.mov(INTER_REG, int_reg_ir_to_host(rs2)) &&
                       emit_x86_rx<op_rr_fn, op_rm_fn>(INTER_REG, rs1) &&
                       move_inter_to_reg(rd);
            } else {
                return move_reg_to_inter(rs1) &&
                       emit_x86_rx<op_rr_fn, op_rm_fn>(INTER_REG, rs2) &&
                       move_inter_to_reg(rd);
            }
        }

#define emit_commutative_rrr(op, rd, rs1, rs2) emit_commutative_rrr<&AsT::op, &AsT::op, &AsT::op>(rd, rs1, rs2)

        template<EmitRT op_r_fn>
        RetT emit_cmp_set_rrr(usize rd, usize rs1, usize rs2) {
            auto inter = asmjit::x86::cl;

            return emit_x86_xx(cmp, rs1, rs2) &&
                   !(as.*op_r_fn)(inter) &&
                   emit_x86_move_zero_xb(rd, inter);
        }

#define emit_cmp_set_rrr(op, rd, rs1, rs2) emit_cmp_set_rrr<&AsT::op>(rd, rs1, rs2)

        template<EmitRRT op_rr_fn, EmitMRT op_mr_fn>
        RetT emit_shift_rrr(usize rd, usize rs1, usize rs2) {
            auto inter = asmjit::x86::cl;

            if (!emit_x86_rx(mov, inter, rs2)) { return false; }

            if (rd == rs1) {
                return emit_x86_xr<op_rr_fn, op_mr_fn>(rd, inter);
            } else {
                return move_reg_to_inter(rs1) &&
                       !(as.*op_rr_fn)(INTER_REG, inter) &&
                       move_inter_to_reg(rd);
            }
        }

#define emit_shift_rrr(op, rd, rs1, rs2) emit_shift_rrr<&AsT::op, &AsT::op>(rd, rs1, rs2)

        template<EmitRRT op_rr_fn1, EmitRMT op_rm_fn1, EmitRRT op_rr_fn2, EmitRMT op_rm_fn2>
        RetT emit_multiply_rrr(usize rd, usize rs1, usize rs2) {
            return emit_x86_rx<op_rr_fn1, op_rm_fn1>(asmjit::x86::rax, rs1) &&
                   emit_x86_rx<op_rr_fn2, op_rm_fn2>(asmjit::x86::rcx, rs2) &&
                   !as.imul(asmjit::x86::rax, asmjit::x86::rcx) &&
                   !as.shr(asmjit::x86::rax, asmjit::Imm{32}) &&
                   emit_x86_xr(mov, rd, asmjit::x86::eax);
        }

#define emit_multiply_rrr(op1, op2, rd, rs1, rs2) \
        emit_multiply_rrr<&AsT::op1, &AsT::op1, &AsT::op2, &AsT::op2>(rd, rs1, rs2)

    public:
        Emitter() : as{} {}

        RetT emit_nop() { return !as.nop(); }

        RetT emit_li_ri(usize rd, i32 imm) {
            if (int_reg_is_host_reg(rd)) {
                auto host_rd = int_reg_ir_to_host(rd);

                if (imm == 0) {
                    if (as.xor_(host_rd, host_rd)) { return false; }
                } else {
                    if (as.mov(host_rd, imm)) { return false; }
                }
            } else {
                auto mem_rd = int_reg_ir_to_mem(rd);

                if (as.mov(mem_rd, imm)) { return false; }
            }

            return true;
        }

#define _neutron_emit_touch(w) \
        RetT emit_t##w##_i(UXLenT addr) { return emit_touch_i<w>(addr); } \
        RetT emit_t##w##_ri(usize rs1, UXLenT addr) { return emit_touch_ri<w>(rs1, addr); }

        _neutron_emit_touch(8);

        _neutron_emit_touch(16);

        _neutron_emit_touch(32);

#undef _neutron_emit_load

#define _neutron_emit_load(w) \
        RetT emit_l##w##_ri(usize rd, UXLenT addr) { return emit_load_ri<w>(rd, addr); } \
        RetT emit_l##w##_rri(usize rd, usize rs1, UXLenT addr) { return emit_load_rri<w>(rd, rs1, addr); }

        _neutron_emit_load(8);

        _neutron_emit_load(16);

        _neutron_emit_load(32);

#undef _neutron_emit_load

#define _neutron_emit_load_u(w) \
        RetT emit_l##w##u_ri(usize rd, UXLenT addr) { return emit_load_u_ri<w>(rd, addr); } \
        RetT emit_l##w##u_rri(usize rd, usize rs1, UXLenT addr) { return emit_load_u_rri<w>(rd, rs1, addr); }

        _neutron_emit_load_u(8);

        _neutron_emit_load_u(16);

#undef _neutron_emit_load_u

#define _neutron_emit_store(w) \
        RetT emit_s##w##_ii(UXLenT addr, XLenT src) { return emit_store_ii<w>(addr, src); } \
        RetT emit_s##w##_ir(UXLenT addr, usize rs2) { return emit_store_ir<w>(addr, rs2); } \
        RetT emit_s##w##_rii(usize rs1, UXLenT base, XLenT src) { return emit_store_rii<w>(rs1, base, src); } \
        RetT emit_s##w##_rir(usize rs1, UXLenT base, usize rs2) { return emit_store_rir<w>(rs1, base, rs2); }

        _neutron_emit_store(8);

        _neutron_emit_store(16);

        _neutron_emit_store(32);

#undef _neutron_emit_store

        RetT emit_t32r_i(UXLenT addr) {
            return (addr == 0 ? !as.xor_(INTER_REG, INTER_REG)
                              : !as.mov(INTER_REG, addr)) &&
                   emit_load_reserve_address(32);
        }

        RetT emit_t32r_r(usize rs1) {
            return emit_x86_rx(mov, INTER_REG, rs1) &&
                   emit_load_reserve_address(32);
        }

        RetT emit_l32r_ri(usize rd, UXLenT addr) {
            return (addr == 0 ? as.xor_(INTER_REG, INTER_REG)
                              : as.mov(INTER_REG, addr)) &&
                   !emit_load_reserve_address(32) &&
                   !emit_x86_xr(mov, rd, asmjit::x86::eax);
        }

        RetT emit_l32r_rr(usize rd, usize rs1) {
            return !emit_x86_rx(mov, INTER_REG, rs1) &&
                   !emit_load_reserve_address(32) &&
                   !emit_x86_xr(mov, rd, asmjit::x86::eax);
        }

        RetT emit_s32c_rii(usize rd, UXLenT addr, XLenT src) {
            (void) rd;
            (void) src;

            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, store_cache.shift));
            auto r_addr = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_address));
            auto r_val = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_value));
//            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, 32);

            auto fail = as.newLabel();
            auto finish = as.newLabel();

            return (addr == 0 ? !as.xor_(INTER_REG, INTER_REG)
                              : !as.mov(INTER_REG, addr)) &&
                   !as.cmp(INTER_REG, r_addr) &&
                   !as.jne(fail) &&
                   emit_address(32, offsetof(struct dynamic_info, store_cache),
                                reinterpret_cast<void *>(&neutron_mmu_store)) &&
                   !as.add(INTER_REG.r64(), shift) &&
                   !as.movsx(asmjit::x86::rax, r_val) &&
                   //                   !as.lock().cmpxchg(ptr, ) && // todo

                   !as.jmp(finish) &&
                   !as.bind(fail) &&
                   !as.mov(asmjit::x86::rax, 1) &&
                   !as.bind(finish);
        }

        RetT emit_s32c_rir(usize rd, UXLenT addr, usize rs2) {
            auto inter = asmjit::x86::cl;

            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, store_cache.shift));
            auto r_addr = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_address));
            auto r_val = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_value));
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, 32);

            auto fail = as.newLabel();
            auto finish = as.newLabel();

            return (addr == 0 ? !as.xor_(INTER_REG, INTER_REG)
                              : !as.mov(INTER_REG, addr)) &&
                   !as.cmp(INTER_REG, r_addr) &&
                   !as.jne(fail) &&
                   emit_address(32, offsetof(struct dynamic_info, store_cache),
                                reinterpret_cast<void *>(&neutron_mmu_store)) &&
                   !as.add(INTER_REG.r64(), shift) &&
                   !as.movsx(asmjit::x86::rax, r_val) &&
                   !as.lock().cmpxchg(ptr, int_reg_ir_to_host(rs2)) && // todo
                   !as.sete(inter) &&
                   emit_x86_move_zero_xb(rd, inter) &&
                   !as.jmp(finish) &&
                   !as.bind(fail) &&
                   emit_li_ri(rd, 1) &&
                   !as.bind(finish);
        }

        RetT emit_s32c_rri(usize rd, usize rs1, XLenT src) {
            (void) rd;
            (void) rs1;
            (void) src;

            return emit_store_conditional_address(32);
        }

        RetT emit_s32c_rrr(usize rd, usize rs1, usize rs2) {
            auto inter = asmjit::x86::cl;

            auto shift = asmjit::x86::ptr_64(asmjit::x86::rbp, offsetof(struct dynamic_info, store_cache.shift));
            auto r_addr = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_address));
            auto r_val = asmjit::x86::ptr_32(asmjit::x86::rbp, offsetof(struct dynamic_info, reserve_value));
            auto ptr = asmjit::x86::ptr(INTER_REG.r64(), 0, 32);

            auto fail = as.newLabel();
            auto finish = as.newLabel();

            return emit_x86_rx(mov, INTER_REG, rs1) &&
                   !as.cmp(INTER_REG, r_addr) &&
                   !as.jne(fail) &&
                   emit_address(32, offsetof(struct dynamic_info, store_cache),
                                reinterpret_cast<void *>(&neutron_mmu_store)) &&
                   !as.add(INTER_REG.r64(), shift) &&
                   !as.movsx(asmjit::x86::rax, r_val) &&
                   !as.lock().cmpxchg(ptr, int_reg_ir_to_host(rs2)) && // todo
                   !as.sete(inter) &&
                   emit_x86_move_zero_xb(rd, inter) &&
                   !as.jmp(finish) &&
                   !as.bind(fail) &&
                   emit_li_ri(rd, 1) &&
                   !as.bind(finish);
        }

        RetT emit_cmp_ri(usize rd, XLenT imm) {
            if (int_reg_is_host_reg(rd)) {
                auto host_rd = int_reg_ir_to_host(rd);

                if (imm == 0) {
                    return !as.cmp(host_rd, imm);
                } else {
                    return !as.test(host_rd, host_rd);
                }
            } else {
                return !as.cmp(int_reg_ir_to_mem(rd), imm);
            }
        }

        RetT emit_move_rr(usize rd, usize rs1) {
            if (rd != rs1) {
                if (int_reg_is_host_reg(rd)) {
                    auto host_rd = int_reg_ir_to_host(rd);

                    if (!(emit_x86_rx(mov, host_rd, rs1))) { return false; }
                } else {
                    auto mem_rd = int_reg_ir_to_mem(rd);

                    if (int_reg_is_host_reg(rs1)) {
                        auto host_rs1 = int_reg_ir_to_host(rd);

                        if (as.mov(mem_rd, host_rs1)) { return false; }
                    } else {
                        auto mem_rs1 = int_reg_ir_to_mem(rs1);

                        if (as.mov(INTER_REG, mem_rs1)) { return false; }
                        if (as.mov(mem_rd, INTER_REG)) { return false; }
                    }
                }
            }

            return true;
        }

        RetT emit_not_rr(usize rd, usize rs1) { return emit_inst_rr(not_, rd, rs1); }

        RetT emit_neg_rr(usize rd, usize rs1) { return emit_inst_rr(neg, rd, rs1); }

        RetT emit_slt_rri(usize rd, usize rs1, XLenT imm) { return emit_cmp_set_rri(setl, rd, rs1, imm); }

        RetT emit_sltu_rri(usize rd, usize rs1, XLenT imm) { return emit_cmp_set_rri(setb, rd, rs1, imm); }

        RetT emit_sgt_rri(usize rd, usize rs1, XLenT imm) { return emit_cmp_set_rri(setg, rd, rs1, imm); }

        RetT emit_sgtu_rri(usize rd, usize rs1, XLenT imm) { return emit_cmp_set_rri(seta, rd, rs1, imm); }

        RetT emit_add_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(add, rd, rs1, imm);
            }
        }

        RetT emit_sub_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(sub, rd, rs1, imm);
            }
        }

        RetT emit_xor_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            }
            if (imm == -1) {
                return emit_not_rr(rd, rs1);
            } else {
                return emit_inst_rri(xor_, rd, rs1, imm);
            }
        }

        RetT emit_or_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else if (imm == -1) {
                return emit_li_ri(rd, -1);
            } else {
                return emit_inst_rri(or_, rd, rs1, imm);
            }
        }

        RetT emit_and_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_li_ri(rd, 0);
            } else if (imm == -1) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(and_, rd, rs1, imm);
            }
        }

        RetT emit_sll_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(shl, rd, rs1, imm);
            }
        }

        RetT emit_srl_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(shr, rd, rs1, imm);
            }
        }

        RetT emit_sra_rri(usize rd, usize rs1, XLenT imm) {
            if (imm == 0) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_inst_rri(sal, rd, rs1, imm);
            }
        }

        RetT emit_slt_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_li_ri(rd, 0);
            } else {
                return emit_cmp_set_rrr(setl, rd, rs1, rs2);
            }
        }

        RetT emit_sltu_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_li_ri(rd, 0);
            } else {
                return emit_cmp_set_rrr(setb, rd, rs1, rs2);
            }
        }

        RetT emit_add_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_sll_rri(rd, rs1, 1);
            } else {
                return emit_commutative_rrr(add, rd, rs1, rs2);
            }
        }

        RetT emit_sub_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_li_ri(rd, 0);
            } else {
                return emit_inst_rrr(sub, rd, rs1, rs2);
            }
        }

        RetT emit_xor_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_li_ri(rd, 0);
            } else {
                return emit_commutative_rrr(xor_, rd, rs1, rs2);
            }
        }

        RetT emit_or_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_commutative_rrr(or_, rd, rs1, rs2);
            }
        }

        RetT emit_and_rrr(usize rd, usize rs1, usize rs2) {
            if (rs1 == rs2) {
                return emit_move_rr(rd, rs1);
            } else {
                return emit_commutative_rrr(and_, rd, rs1, rs2);
            }
        }

        RetT emit_sll_rrr(usize rd, usize rs1, usize rs2) {
            return emit_shift_rrr(shl, rd, rs1, rs2);
        }

        RetT emit_srl_rrr(usize rd, usize rs1, usize rs2) {
            return emit_shift_rrr(shr, rd, rs1, rs2);
        }

        RetT emit_sra_rrr(usize rd, usize rs1, usize rs2) {
            return emit_shift_rrr(sal, rd, rs1, rs2);
        }

        RetT emit_mul_rrr(usize rd, usize rs1, usize rs2) {
            if (int_reg_is_host_reg(rd)) {
                auto host_rd = int_reg_ir_to_host(rd);

                if (rd == rs1) {
                    return emit_x86_rx(imul, host_rd, rs2);
                } else if (rd == rs2) {
                    return emit_x86_rx(imul, host_rd, rs1);
                }
            }

            if (int_reg_is_host_reg(rs2)) {
                return move_reg_to_inter(rs2) &&
                       emit_x86_rx(imul, INTER_REG, rs1) &&
                       move_inter_to_reg(rd);
            } else {
                return move_reg_to_inter(rs1) &&
                       emit_x86_rx(imul, INTER_REG, rs2) &&
                       move_inter_to_reg(rd);
            }
        }

        RetT emit_mulh_rrr(usize rd, usize rs1, usize rs2) {
            return emit_multiply_rrr(movsx, movsx, rd, rs1, rs2);
        }

        RetT emit_mulhsu_rrr(usize rd, usize rs1, usize rs2) {
            return emit_multiply_rrr(movsx, movzx, rd, rs1, rs2);
        }

        RetT emit_mulhu_rrr(usize rd, usize rs1, usize rs2) {
            return emit_multiply_rrr(movzx, movzx, rd, rs1, rs2);
        }

        RetT emit_div_rrr(usize rd, usize rs1, usize rs2) {
            auto end = as.newLabel();
            auto not_divide_by_zero = as.newLabel();
            auto not_overflow = as.newLabel();

            return emit_cmp_ri(rs2, 0) &&
                   !as.jne(not_divide_by_zero) &&                       // if (rs2 == 0) {
                   emit_li_ri(rd, -1) &&                                // rd = -1
                   !as.jmp(end) &&
                   !as.bind(not_divide_by_zero) &&
                   emit_cmp_ri(rs2, -1) &&
                   !as.jne(not_overflow) &&                             // } else if (rs2 == -1 &&
                   emit_cmp_ri(rs1, xlen::XLEN_MIN) &&
                   !as.jne(not_overflow) &&                             // rs1 == XLEN_MIN) {
                   emit_move_rr(rd, rs1) &&                             // rd = XLEN_MIN
                   !as.jmp(end) &&
                   !as.bind(not_overflow) &&                            // } else { rd = rs1 / rs2 }
                   !as.mov(int_reg_ir_to_mem(0), asmjit::x86::edx) &&   // save edx
                   emit_x86_rx(mov, asmjit::x86::eax, rs1) &&
                   !as.cqo() &&                                         // sign extend edx
                   (int_reg_is_host_reg(rs2) ? !as.idiv(int_reg_ir_to_host(rs2))
                                             : !as.idiv(int_reg_ir_to_mem(rs2))) &&
                   emit_x86_xr(mov, rd, asmjit::x86::eax) &&
                   !as.mov(asmjit::x86::edx, int_reg_ir_to_mem(0)) &&   // restore edx
                   !as.bind(end);
        }

        RetT emit_divu_rrr(usize rd, usize rs1, usize rs2) {
            auto end = as.newLabel();
            auto not_divide_by_zero = as.newLabel();

            return emit_cmp_ri(rs2, 0) &&
                   !as.jne(not_divide_by_zero) &&                       // if (rs2 == 0) {
                   emit_li_ri(rd, -1) &&                                // rd = -1
                   !as.jmp(end) &&
                   !as.bind(not_divide_by_zero) &&                      // } else { rd = rs1 / rs2 }
                   !as.mov(int_reg_ir_to_mem(0), asmjit::x86::edx) &&   // save edx
                   emit_x86_rx(mov, asmjit::x86::eax, rs1) &&
                   !as.xor_(asmjit::x86::edx, asmjit::x86::edx) &&      // zero extend edx
                   (int_reg_is_host_reg(rs2) ? !as.div(int_reg_ir_to_host(rs2))
                                             : !as.div(int_reg_ir_to_mem(rs2))) &&
                   emit_x86_xr(mov, rd, asmjit::x86::eax) &&
                   !as.mov(asmjit::x86::edx, int_reg_ir_to_mem(0)) &&   // restore edx
                   !as.bind(end);
        }

        RetT emit_rem_rrr(usize rd, usize rs1, usize rs2) {
            auto end = as.newLabel();
            auto not_divide_by_zero = as.newLabel();
            auto not_overflow = as.newLabel();

            return emit_cmp_ri(rs2, 0) &&
                   !as.jne(not_divide_by_zero) &&                       // if (rs2 == 0) {
                   emit_move_rr(rd, rs1) &&                             // rd = rs1
                   !as.jmp(end) &&
                   !as.bind(not_divide_by_zero) &&
                   emit_cmp_ri(rs2, -1) &&
                   !as.jne(not_overflow) &&                             // } else if (rs2 == -1 &&
                   emit_cmp_ri(rs1, xlen::XLEN_MIN) &&
                   !as.jne(not_overflow) &&                             // rs1 == XLEN_MIN) {
                   emit_li_ri(rd, 0) &&                                 // rd = 0
                   !as.jmp(end) &&
                   !as.bind(not_overflow) &&                            // } else { rd = rs1 % rs2 }
                   !as.mov(int_reg_ir_to_mem(0), asmjit::x86::edx) &&   // save edx
                   emit_x86_rx(mov, asmjit::x86::eax, rs1) &&
                   !as.cqo() &&                                         // sign extend edx
                   (int_reg_is_host_reg(rs2) ? !as.idiv(int_reg_ir_to_host(rs2))
                                             : !as.idiv(int_reg_ir_to_mem(rs2))) &&
                   emit_x86_xr(mov, rd, asmjit::x86::edx) &&
                   !as.mov(asmjit::x86::edx, int_reg_ir_to_mem(0)) &&   // restore edx
                   !as.bind(end);
        }

        RetT emit_remu_rrr(usize rd, usize rs1, usize rs2) {
            auto end = as.newLabel();
            auto not_divide_by_zero = as.newLabel();

            return emit_cmp_ri(rs2, 0) &&
                   !as.jne(not_divide_by_zero) &&                       // if (rs2 == 0) {
                   emit_move_rr(rd, rs1) &&                             // rd = rs1
                   !as.jmp(end) &&
                   !as.bind(not_divide_by_zero) &&                      // } else { rd = rs1 % rs2 }
                   !as.mov(int_reg_ir_to_mem(0), asmjit::x86::edx) &&   // save edx
                   emit_x86_rx(mov, asmjit::x86::eax, rs1) &&
                   !as.xor_(asmjit::x86::edx, asmjit::x86::edx) &&      // zero extend edx
                   (int_reg_is_host_reg(rs2) ? !as.div(int_reg_ir_to_host(rs2))
                                             : !as.div(int_reg_ir_to_mem(rs2))) &&
                   emit_x86_xr(mov, rd, asmjit::x86::edx) &&
                   !as.mov(asmjit::x86::edx, int_reg_ir_to_mem(0)) &&   // restore edx
                   !as.bind(end);
        }
    };

    template<typename xlen>
    const asmjit::x86::Gp Emitter<xlen>::INTER_REG = asmjit::x86::ecx;
}


#endif //NEUTRON_EMITTER_HPP
