#ifndef NEUTRON_GRAPH_HPP
#define NEUTRON_GRAPH_HPP


#include <map>
#include <set>


namespace neutron {
    template<typename T>
    class Graph {
    private:
        std::map<T, std::pair<std::set<T>, std::set<T>>> inner;

    public:
        using VertexSet = std::set<T> &;
        using VertexIter = typename std::set<T>::iterator;

        class VertexPtr : public std::map<T, std::pair<std::set<T>, std::set<T>>>::iterator {
        private:
            using InnerT = typename std::map<T, std::pair<std::set<T>, std::set<T>>>::iterator;

        public:
            VertexPtr(InnerT iter) : InnerT{iter} {}

            T get_vertex() { return this->operator->()->first; }
            VertexSet get_predecessor() { return this->operator->()->second.first; }
            VertexSet get_successor() { return this->operator->()->second.second; }
        };

        Graph() : inner{} {}

        void add_vertex(T a, T b) {
            inner[a].second.emplace(b);
            inner[b].first.emplace(a);
        }

        VertexPtr find_vertex(T a) { return inner.find(a); }

        VertexPtr begin() { return inner.begin(); }

        VertexPtr end() { return inner.end(); }
    };
}


#endif //NEUTRON_GRAPH_HPP
