#ifndef NEUTRON_BRANCH_TABLE_HPP
#define NEUTRON_BRANCH_TABLE_HPP


#include <unordered_set>
#include <unordered_map>

#include "neutron_utility.hpp"
#include "riscv_linux_fuzzer.hpp"


namespace neutron {
    template<typename xlen>
    class BranchTable {
    public:
        using UXLenT = typename xlen::UXLenT;

        using SeedSet = std::unordered_set<SeedPool::SeedIDT>;
        using BranchMapT = std::unordered_map<UXLenT, usize>;

    private:
        const BranchMapT branch_map;
        const BranchMapT jump_map;
        Array<std::pair<SeedSet, SeedSet>> branch_table;
        Array<std::unordered_map<UXLenT, SeedSet>> jump_table;

    public:
        BranchTable(BranchMapT &&_branch_map, BranchMapT &&_jump_map) :
                branch_map{std::move(_branch_map)}, jump_map{std::move(_jump_map)},
                branch_table(branch_map.size()), jump_table(jump_map.size()) {}

        BranchTable(const BranchTable<UXLenT> &other) = delete;

        BranchTable &operator=(const BranchTable<UXLenT> &other) = delete;

        bool add_seed(SeedPool::SeedIDT id, const typename LinuxFuzzerCore<xlen>::BranchRecordT &record) {
            Array<std::pair<bool, bool>> branch(branch_map.size());
            Array<std::unordered_set<UXLenT>> jump(jump_map.size());

            for (auto &item: record) {
                bool result;

                switch (item.type) {
                    case BranchRecord<xlen>::JAL:
                        continue;
                    case BranchRecord<xlen>::JALR: {
                        auto offset = jump_map.find(item.address);

                        if (offset != jump_map.end()) {
                            jump[offset->second].emplace(item.get_target());
                        }
                    }
                        continue;
                    case BranchRecord<xlen>::BEQ:
                        result = riscv_isa::operators::EQ<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    case BranchRecord<xlen>::BNE:
                        result = riscv_isa::operators::NE<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    case BranchRecord<xlen>::BLT:
                        result = riscv_isa::operators::LT<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    case BranchRecord<xlen>::BGE:
                        result = riscv_isa::operators::GE<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    case BranchRecord<xlen>::BLTU:
                        result = riscv_isa::operators::LTU<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    case BranchRecord<xlen>::BGEU:
                        result = riscv_isa::operators::GEU<xlen>::op(item.get_op1(), item.get_op2());
                        break;
                    default:
                        neutron_unreachable("unknown type!");
                }

                auto offset = branch_map.find(item.address);

                if (offset != branch_map.end()) {
                    if (result) {
                        branch[offset->second].first = true;
                    } else {
                        branch[offset->second].second = true;
                    }
                }
            }

            bool new_met = false;

            for (usize i = 0; i < branch_map.size(); ++i) {
                if (branch[i].first) {
                    if (branch_table[i].first.empty()) { new_met = true; }
                    branch_table[i].first.emplace(id);
                }
                if (branch[i].second) {
                    if (branch_table[i].second.empty()) { new_met = true; }
                    branch_table[i].second.emplace(id);
                }
            }

            for (usize i = 0; i < jump_map.size(); ++i) {
                for (auto &item: jump[i]) {
                    auto pair = jump_table[i].emplace(item, SeedSet{});

                    if (pair.second) { new_met = true; }
                    pair.first->second.emplace(id);
                }
            }

            return new_met;
        }



        ~BranchTable() = default;
    };
}


#endif //NEUTRON_BRANCH_TABLE_HPP
