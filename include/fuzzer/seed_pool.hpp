#ifndef NEUTRON_SEED_POOL_HPP
#define NEUTRON_SEED_POOL_HPP


#include <unordered_map>
#include <unordered_set>
#include <memory>


namespace neutron {
    class SeedPool {
    public:
        using SeedIDT = u64;
        using SeedT = std::unordered_map<std::string, std::shared_ptr<Array<u8>>>;
        using SeedMapT = std::unordered_map<SeedIDT, SeedT>;

    private:
        SeedMapT seed_map;
        std::random_device rand;

    public:
        SeedPool() : seed_map{}, rand{} {}

        SeedPool(const SeedPool &other) = delete;

        SeedPool &operator=(const SeedPool &other) = delete;

        SeedIDT insert_seed(SeedT &&seed) {
            SeedIDT id = rand();

            // critical section
            while (seed_map.find(id) != seed_map.end()) { id = rand(); }
            auto ptr = seed_map.emplace(id, std::move(seed)).first;
            // ----------------

            return ptr->first;
        }

        SeedIDT insert_seed(const SeedT &_seed) {
            SeedT seed = _seed;
            return insert_seed(std::move(seed));
        }

        const SeedT &get_seed(SeedIDT id) const {
            // critical section
            auto ptr = seed_map.find(id);
            // ----------------
            if (ptr == seed_map.end()) { neutron_abort("seed not found!"); }

            return ptr->second;
        }

        ~SeedPool() = default;
    };
}


#endif //NEUTRON_SEED_POOL_HPP
