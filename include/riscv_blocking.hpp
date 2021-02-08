#ifndef NEUTRON_RISCV_BLOCKING_HPP
#define NEUTRON_RISCV_BLOCKING_HPP


#include <cstring>
#include <map>

#include "instruction/instruction_visitor.hpp"

#include "neutron_utility.hpp"
#include "graph.hpp"


namespace neutron {
    class BlockVisitor : public riscv_isa::InstructionVisitor<BlockVisitor, usize> {
    public:
        using UXLenT = riscv_isa::xlen_trait::UXLenT;
        using BranchMapT = std::unordered_map<UXLenT, usize>;

    private:
        std::map<UXLenT, std::pair<UXLenT, UXLenT>> block;
        BranchMapT &branch;
        BranchMapT &indirect;
        UXLenT inst_offset;

        static bool is_link(usize reg) { return reg == 1 || reg == 5; }

        UXLenT regularize_addr(UXLenT addr, UXLenT guest, usize size) {
            if (addr < guest || addr >= guest + size) {
                return 0;
            } else {
                auto iter = block.upper_bound(addr - 1);
                return iter == block.end() ? 0 : iter->first;
            }
        }

        BlockVisitor(BranchMapT &branch, BranchMapT &indirect)
                : block{}, branch{branch}, indirect{indirect}, inst_offset{0} {}

        Graph<UXLenT> blocking(UXLenT guest, void *host, usize size) {
            usize offset = 0;

            while (offset < size) {
                inst_offset = guest + offset;
                u8 *inst = static_cast<u8 *>(host) + offset;
                usize inc = visit_in_memory(reinterpret_cast<riscv_isa::Instruction *>(inst), size - offset);
                if (inc == 0) break;
                offset += inc;
            }

            Graph<UXLenT> graph{};

            for (auto &item: block) {
                UXLenT vertex = item.first;

                graph.add_vertex(vertex, regularize_addr(item.second.first, guest, size));
                if (item.second.first != item.second.second)
                    graph.add_vertex(vertex, regularize_addr(item.second.second, guest, size));
            }

            return graph;
        }

    public:
        RetT illegal_instruction(neutron_unused const riscv_isa::Instruction *inst) { return 0; }

        template<typename InstT>
        RetT log_branch(InstT *inst) {
            block.emplace(inst_offset, std::make_pair(
                    inst_offset + InstT::INST_WIDTH,
                    inst_offset + inst->get_imm()
            ));
            branch.emplace(inst_offset, branch.size());
            return InstT::INST_WIDTH;
        }

        template<typename InstT>
        struct _return_inst_len {
            static RetT inner(BlockVisitor *self, const InstT *inst);
        };

        template<typename InstT>
        RetT return_inst_len(const InstT *inst) {
            return _return_inst_len<InstT>::inner(this, inst);
        }

#define _neutron_return_inst_len(NAME, name) \
        RetT visit_##name##_inst(const riscv_isa::NAME##Inst *inst) { return return_inst_len(inst); }

        riscv_isa_instruction_map(_neutron_return_inst_len)

#undef _neutron_return_inst_len

        static Graph<UXLenT> build(UXLenT guest, void *host, usize size, BranchMapT &branch, BranchMapT &indirect) {
            return BlockVisitor{branch, indirect}.blocking(guest, host, size);
        }
    };

    template<typename InstT>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<InstT>::inner(
            neutron_unused BlockVisitor *self, neutron_unused const InstT *inst
    ) { return InstT::INST_WIDTH; }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::JALInst>::inner(
            BlockVisitor *self, const riscv_isa::JALInst *inst
    ) {
        if (is_link(inst->get_rd())) {
            // direct function call
            UXLenT next_inst = self->inst_offset + riscv_isa::JALInst::INST_WIDTH;
            self->block.emplace(self->inst_offset, std::make_pair(next_inst, next_inst));
        } else {
            // direct jump
            usize target = self->inst_offset + inst->get_imm();
            self->block.emplace(self->inst_offset, std::make_pair(target, target));
        }

        return riscv_isa::JALInst::INST_WIDTH;
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::JALRInst>::inner(
            BlockVisitor *self, const riscv_isa::JALRInst *inst
    ) {
        self->indirect.emplace(self->inst_offset, self->indirect.size());

        if (is_link(inst->get_rd())) {
            // indirect function call
            UXLenT next_inst = self->inst_offset + riscv_isa::JALRInst::INST_WIDTH;
            self->block.emplace(self->inst_offset, std::make_pair(next_inst, next_inst));
        } else {
            // indirect jump
            self->block.emplace(self->inst_offset, std::make_pair(0, 0));
        }

        return riscv_isa::JALRInst::INST_WIDTH;
    }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BEQInst>::inner(
            BlockVisitor *self, const riscv_isa::BEQInst *inst
    ) { return self->log_branch(inst); }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BNEInst>::inner(
            BlockVisitor *self, const riscv_isa::BNEInst *inst
    ) { return self->log_branch(inst); }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BLTInst>::inner(
            BlockVisitor *self, const riscv_isa::BLTInst *inst
    ) { return self->log_branch(inst); }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BGEInst>::inner(
            BlockVisitor *self, const riscv_isa::BGEInst *inst
    ) { return self->log_branch(inst); }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BLTUInst>::inner(
            BlockVisitor *self, const riscv_isa::BLTUInst *inst
    ) { return self->log_branch(inst); }

    template<>
    BlockVisitor::RetT BlockVisitor::_return_inst_len<riscv_isa::BGEUInst>::inner(
            BlockVisitor *self, const riscv_isa::BGEUInst *inst
    ) { return self->log_branch(inst); }
}


#endif //NEUTRON_RISCV_BLOCKING_HPP
