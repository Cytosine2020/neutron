#ifndef NEUTRON_RISCV_BLOCKING_HPP
#define NEUTRON_RISCV_BLOCKING_HPP


#include <map>

#include "instruction/instruction_visitor.hpp"

#include "neutron_utility.hpp"
#include "graph.hpp"


namespace neutron {
    class BlockVisitor : public riscv_isa::InstructionVisitor<BlockVisitor, usize> {
    private:
        using UXLenT = riscv_isa::xlen_trait::UXLenT;

        std::map<UXLenT, std::pair<UXLenT, UXLenT>> block;
        UXLenT inst_offset;
        riscv_isa::ILenT inst_buffer;

        static bool is_link(usize reg) { return reg == 1 || reg == 5; }

        UXLenT reularize_addr(UXLenT addr, UXLenT guest, usize size) {
            if (addr < guest || addr >= guest + size) {
                return 0;
            } else {
                auto iter = block.upper_bound(addr - 1);
                return iter == block.end() ? 0 : iter->first;
            }
        }

        BlockVisitor() : block{}, inst_offset{0}, inst_buffer{0} {}

        Graph<UXLenT> blocking(UXLenT guest, void *host, usize size) {
            usize offset = 0;

            while (offset < size) {
                inst_offset = guest + offset;
                u8 *inst = static_cast<u8 *>(host) + offset;
                usize inc = visit(reinterpret_cast<riscv_isa::Instruction *>(inst), size - offset);
                if (inc == 0) break;
                offset += inc;
            }

            Graph<UXLenT> graph{};

            for (auto &item: block) {
                UXLenT vertex = item.first;

                graph.add_vertex(vertex, reularize_addr(item.second.first, guest, size));
                if (item.second.first != item.second.second)
                    graph.add_vertex(vertex, reularize_addr(item.second.second, guest, size));
            }

            return graph;
        }

        RetT visit(riscv_isa::Instruction *inst, usize length) {
            inst_buffer = 0;

            if (length < 2) return illegal_instruction(reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer));
            *(reinterpret_cast<u16 *>(&inst_buffer) + 0) = *(reinterpret_cast<u16 *>(inst) + 0);

            if ((this->inst_buffer & bits_mask<u16, 2, 0>::val) != bits_mask<u16, 2, 0>::val) {
#if defined(__RV_EXTENSION_C__)
                return this->visit_16(reinterpret_cast<Instruction16 *>(&this->inst_buffer));
#else
                return illegal_instruction(reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer));
#endif // defined(__RV_EXTENSION_C__)
            } else if ((this->inst_buffer & bits_mask<u16, 5, 2>::val) != bits_mask<u16, 5, 2>::val) {
                if (length < 4)
                    return illegal_instruction(reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer));
                *(reinterpret_cast<u16 *>(&inst_buffer) + 1) = *(reinterpret_cast<u16 *>(inst) + 1);
                return this->visit_32(reinterpret_cast<riscv_isa::Instruction32 *>(&this->inst_buffer));
            } else {
                return illegal_instruction(reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer));
            }
        }

    public:
        RetT illegal_instruction(neutron_unused riscv_isa::Instruction *inst) { return 0; }

        template<typename InstT>
        RetT log_branch(InstT *inst) {
            block.emplace(inst_offset, std::make_pair(inst_offset + InstT::INST_WIDTH, inst_offset + inst->get_imm()));
            return InstT::INST_WIDTH;
        }

        template<typename InstT>
        struct _return_inst_len {
            static RetT inner(neutron_unused BlockVisitor *self, neutron_unused InstT *inst);
        };

        template<typename InstT>
        RetT return_inst_len(neutron_unused InstT *inst) { return _return_inst_len<InstT>::inner(this, inst); }

#define _neutron_return_inst_len(NAME, name) \
        RetT visit_##name##_inst(riscv_isa::NAME##Inst *inst) { return return_inst_len(inst); }

        riscv_isa_instruction_map(_neutron_return_inst_len)

#undef _neutron_return_inst_len

        static Graph<UXLenT> build(UXLenT guest, void *host, usize size) {
            return BlockVisitor{}.blocking(guest, host, size);
        }
    };

    template<typename InstT>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<InstT>::inner(
            neutron_unused BlockVisitor *self, neutron_unused InstT *inst
    ) {
        return InstT::INST_WIDTH;
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::JALInst>::inner(
            BlockVisitor *self, riscv_isa::JALInst *inst
    ) {
        if (is_link(inst->get_rd())) {
            UXLenT next_inst = self->inst_offset + riscv_isa::JALInst::INST_WIDTH;
            self->block.emplace(self->inst_offset, std::make_pair(next_inst, next_inst));
        } else {
            usize target = self->inst_offset + inst->get_imm();
            self->block.emplace(self->inst_offset, std::make_pair(target, target));
        }

        return riscv_isa::JALInst::INST_WIDTH;
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::JALRInst>::inner(
            BlockVisitor *self, riscv_isa::JALRInst *inst
    ) {
        if (is_link(inst->get_rd())) {
            UXLenT next_inst = self->inst_offset + riscv_isa::JALRInst::INST_WIDTH;
            self->block.emplace(self->inst_offset, std::make_pair(next_inst, next_inst));
        } else {
            self->block.emplace(self->inst_offset, std::make_pair(0, 0)); // zero stands for return to caller
        }

        return riscv_isa::JALRInst::INST_WIDTH;
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BEQInst>::inner(
            BlockVisitor *self, riscv_isa::BEQInst *inst
    ) {
        return self->log_branch(inst);
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BNEInst>::inner(
            BlockVisitor *self, riscv_isa::BNEInst *inst
    ) {
        return self->log_branch(inst);
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BLTInst>::inner(
            BlockVisitor *self, riscv_isa::BLTInst *inst
    ) {
        return self->log_branch(inst);
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BGEInst>::inner(
            BlockVisitor *self, riscv_isa::BGEInst *inst
    ) {
        return self->log_branch(inst);
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BLTUInst>::inner(
            BlockVisitor *self, riscv_isa::BLTUInst *inst
    ) {
        return self->log_branch(inst);
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BGEUInst>::inner(
            BlockVisitor *self, riscv_isa::BGEUInst *inst
    ) {
        return self->log_branch(inst);
    }
}


#endif //NEUTRON_RISCV_BLOCKING_HPP
