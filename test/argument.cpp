#include <iostream>
#include <sys/auxv.h>

extern char **environ;


int main(int argc, char **argv) {
    char **envp = environ;

    std::cout << "argc: " << argc << std::endl;
    std::cout << "argv: " << argv << std::endl;
    std::cout << "envp: " << envp << std::endl;

    for (size_t i = 0; i < argc; ++i) {
        std::cout << reinterpret_cast<void *>(argv[i]) << ": " << argv[i] << std::endl;
    }

    std::cout << reinterpret_cast<void *>(argv[argc]) << std::endl;

    for (size_t i = 0; environ[i] != nullptr; ++i) {
        std::cout << reinterpret_cast<void *>(environ[i]) << ": " << envp[i] << std::endl;
    }

#define getauxval(type) \
    std::cout << #type ": " << getauxval(type) << std::endl;

    getauxval(AT_IGNORE);
    getauxval(AT_EXECFD);
    getauxval(AT_PHDR);
    getauxval(AT_PHENT);
    getauxval(AT_PHNUM);
    getauxval(AT_PAGESZ);
    getauxval(AT_BASE);
    getauxval(AT_FLAGS);
    getauxval(AT_ENTRY);
    getauxval(AT_NOTELF);
    getauxval(AT_UID);
    getauxval(AT_EUID);
    getauxval(AT_GID);
    getauxval(AT_EGID);
    getauxval(AT_PLATFORM);
    getauxval(AT_HWCAP);
    getauxval(AT_CLKTCK);
    getauxval(AT_SECURE);
    getauxval(AT_BASE_PLATFORM);
    getauxval(AT_RANDOM);
    getauxval(AT_PHNUM);
    getauxval(AT_HWCAP2);
    getauxval(AT_EXECFN);
    getauxval(AT_SYSINFO);
    getauxval(AT_SYSINFO_EHDR);
}
