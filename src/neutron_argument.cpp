#include "neutron_argument.hpp"

#include <vector>
#include <unordered_map>

#include "neutron_utility.hpp"


namespace neutron {
std::pair<ArgumentT, EnviromentT>
process_argument(int argc, const char *const *argv, const char *const *envp) {
    ArgumentT argument{};
    EnviromentT environment{}, new_environment{};

    for (int i = 1; i < argc; ++i) { argument.emplace_back(argv[i]); }

    for (usize envc = 0; envp[envc] != nullptr; ++envc) {
        const char *key = envp[envc];
        const char *value = strchr(envp[envc], '=');

        environment.emplace(std::string{key, value}, std::string{value + 1});
    }

    environment.erase("LD_LIBRARY_PATH");
    environment.erase("LD_PRELOAD");
    environment.erase("RISCV_SYSROOT");

    for (auto &pair: environment) {
        if (pair.first.rfind("NEUTRON_", 0) == 0) {
            new_environment[pair.first.substr(strlen("NEUTRON_"))] = pair.second;
        } else {
            new_environment[pair.first] = pair.second;
        }
    }

    return std::make_pair(argument, new_environment);
}
}
