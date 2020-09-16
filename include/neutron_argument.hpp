#ifndef NEUTRON_NEUTRON_ARGUMENT_HPP
#define NEUTRON_NEUTRON_ARGUMENT_HPP


#include <vector>
#include <unordered_map>


namespace neutron {
    using ArgumentT = std::vector<std::string>;
    using EnviromentT = std::unordered_map<std::string, std::string>;

    std::pair<ArgumentT, EnviromentT> process_argument(int argc, const char *const *argv, const char *const *envp);
}


#endif //NEUTRON_NEUTRON_ARGUMENT_HPP
