#ifndef NEUTRON_DOMINATOR_TREE_HPP
#define NEUTRON_DOMINATOR_TREE_HPP


#include <vector>
#include <unordered_map>

#include "neutron_utility.hpp"
#include "graph.hpp"

namespace neutron {
    template<typename VertexT, bool post>
    class DominatorTree;

    template<typename VertexT, bool post, bool direction>
    struct _get_relate_vertex {
        using VertexSet = typename DominatorTree<VertexT, post>::VertexSet;
        using VertexPtr = typename DominatorTree<VertexT, post>::VertexPtr;

        static VertexSet inner(VertexPtr vertex);
    };

    template<typename VertexT, bool post>
    struct _get_relate_vertex<VertexT, post, true> {
        using VertexSet = typename DominatorTree<VertexT, post>::VertexSet;
        using VertexPtr = typename DominatorTree<VertexT, post>::VertexPtr;

        static VertexSet inner(VertexPtr vertex) { return vertex.get_successor(); }
    };

    template<typename VertexT, bool post>
    struct _get_relate_vertex<VertexT, post, false> {
        using VertexSet = typename DominatorTree<VertexT, post>::VertexSet;
        using VertexPtr = typename DominatorTree<VertexT, post>::VertexPtr;

        static VertexSet inner(VertexPtr vertex) { return vertex.get_predecessor(); }
    };


    template<typename VertexT, bool post = false>
    class DominatorTree {
    public:
        using GraghT = Graph<VertexT>;
        using VertexSet = typename GraghT::VertexSet;
        using VertexPtr = typename GraghT::VertexPtr;
        using VertexIter = typename GraghT::VertexIter;

    private:
        struct VertexInfo {
            usize index;
            usize label;
            usize parent;
            usize ancestor;
            usize semi;
            usize idom;
        };

        VertexT entry;
        GraghT &graph;
        std::vector<VertexT> vertex;
        std::unordered_map<VertexT, VertexInfo> vertex_info;

        template<bool direction>
        static VertexSet get_relate_vertex(VertexPtr vertex) {
            return _get_relate_vertex<VertexT, post, direction>::inner(vertex);
        }

        explicit DominatorTree(GraghT &graph, VertexT entry) : entry{entry}, graph{graph}, vertex{}, vertex_info{} {};

        void depth_first_search() {
            vertex.clear();
            vertex_info.clear();

            VertexPtr start = graph.find_vertex(entry);
            if (start == graph.end()) {
                vertex.resize(1, VertexT{});
                return;
            }

            vertex_info.emplace(0, VertexInfo{
                    .index = 1,
                    .label = 1,
                    .parent = 0,
                    .ancestor = 0,
                    .semi = 0,
                    .idom = 0});

            std::vector<std::pair<VertexPtr, VertexIter>> stack{{start, get_relate_vertex<!post>(start).begin()}};

            usize count = 2;
            while (!stack.empty()) {
                auto back = stack.back();
                stack.pop_back();

                while (back.second != get_relate_vertex<!post>(back.first).end()) {
                    VertexT current_vertex = *(back.second++);
                    if (vertex_info.find(current_vertex) == vertex_info.end()) {
                        usize current = count++;
                        usize predecessor = vertex_info[back.first.get_vertex()].index;

                        vertex_info.emplace(current_vertex, VertexInfo{
                                .index = current,
                                .label = current,
                                .parent = predecessor,
                                .ancestor = 0,
                                .semi = predecessor,
                                .idom = predecessor});
                        stack.emplace_back(back.first, back.second);

                        VertexPtr current_ptr = graph.find_vertex(current_vertex);
                        stack.emplace_back(current_ptr, get_relate_vertex<!post>(current_ptr).begin());
                        break;
                    }
                }
            }

            vertex.resize(count, VertexT{});
            vertex[1] = entry;
            for (auto &item: vertex_info)
                vertex[item.second.index] = item.first;
        }

        void compress(VertexT v) {
            std::vector<VertexT> stack{};

            VertexT current = v;
            VertexT ancestor = vertex[vertex_info[current].ancestor];

            while (vertex_info[ancestor].ancestor != 0) {
                stack.emplace_back(current);
                current = ancestor;
                ancestor = vertex[vertex_info[current].ancestor];
            }

            while (!stack.empty()) {
                ancestor = current;
                current = stack.back();
                stack.pop_back();

                VertexInfo &current_info = vertex_info[current];
                VertexInfo &ancestor_info = vertex_info[ancestor];

                if (ancestor_info.label < current_info.label)
                    current_info.label = ancestor_info.label;

                current_info.ancestor = ancestor_info.ancestor;
            }
        }

        std::map<VertexT, VertexT> semi_nca() {
            depth_first_search();

            for (usize i = vertex.size() - 1; i > 1; --i) {
                VertexT w = vertex[i];
                VertexInfo &w_info = vertex_info[w];

                for (auto &v: get_relate_vertex<post>(graph.find_vertex(w))) {
                    VertexInfo &v_info = vertex_info[v];

                    compress(v);
                    if (v_info.label < w_info.semi)
                        w_info.semi = v_info.label;
                }
                w_info.label = w_info.semi;
                w_info.ancestor = w_info.parent;
            }

            for (usize i = 2; i < vertex.size(); ++i) {
                VertexT v = vertex[i];
                VertexInfo &v_info = vertex_info[v];
                usize v_idom = v_info.idom;

                while (v_idom > v_info.semi)
                    v_idom = vertex_info[vertex[v_idom]].idom;

                v_info.idom = v_idom;
            }

            std::map<VertexT, VertexT> dominator{};

            for (auto block = graph.begin(); block != graph.end(); ++block) {
                VertexT v = block.get_vertex();
                if (v != entry) {
                    auto v_info = vertex_info.find(v);
                    dominator.emplace(v, v_info == vertex_info.end() ? entry : vertex[v_info->second.idom]);
                }
            }

            return dominator;
        }

    public:

        static std::map<VertexT, VertexT> build(GraghT &graph, VertexT entry) {
            return DominatorTree{graph, entry}.semi_nca();
        }
    };

    template<typename VertexT>
    using PosDominatorTree = DominatorTree<VertexT, false>;
}


#endif //NEUTRON_DOMINATOR_TREE_HPP
