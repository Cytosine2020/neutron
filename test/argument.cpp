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

    std::cout << "AT_IGNORE: " << getauxval(AT_IGNORE) << std::endl;
    std::cout << "AT_EXECFD: " << getauxval(AT_EXECFD) << std::endl;
    std::cout << "AT_PHDR: " << getauxval(AT_PHDR) << std::endl;
    std::cout << "AT_PHENT: " << getauxval(AT_PHENT) << std::endl;
    std::cout << "AT_PHNUM: " << getauxval(AT_PHNUM) << std::endl;
    std::cout << "AT_PAGESZ: " << getauxval(AT_PAGESZ) << std::endl;
    std::cout << "AT_BASE: " << getauxval(AT_BASE) << std::endl;
    std::cout << "AT_FLAGS: " << getauxval(AT_FLAGS) << std::endl;
    std::cout << "AT_ENTRY: " << getauxval(AT_ENTRY) << std::endl;
    std::cout << "AT_NOTELF: " << getauxval(AT_NOTELF) << std::endl;
    std::cout << "AT_UID: " << getauxval(AT_UID) << std::endl;
    std::cout << "AT_EUID: " << getauxval(AT_EUID) << std::endl;
    std::cout << "AT_GID: " << getauxval(AT_GID) << std::endl;
    std::cout << "AT_EGID: " << getauxval(AT_EGID) << std::endl;
    std::cout << "AT_PLATFORM: " << reinterpret_cast<const char *>(getauxval(AT_PLATFORM)) << std::endl;
    std::cout << "AT_HWCAP: " << getauxval(AT_HWCAP) << std::endl;
    std::cout << "AT_CLKTCK: " << getauxval(AT_CLKTCK) << std::endl;
    std::cout << "AT_SECURE: " << getauxval(AT_SECURE) << std::endl;
    std::cout << "AT_BASE_PLATFORM: " << getauxval(AT_BASE_PLATFORM) << std::endl;
    std::cout << "AT_RANDOM: " << getauxval(AT_RANDOM) << std::endl;
    std::cout << "AT_HWCAP2: " << getauxval(AT_HWCAP2) << std::endl;
    std::cout << "AT_EXECFN: " << reinterpret_cast<const char *>(getauxval(AT_EXECFN)) << std::endl;
    std::cout << "AT_SYSINFO: " << getauxval(AT_SYSINFO) << std::endl;
    std::cout << "AT_SYSINFO_EHDR: " << getauxval(AT_SYSINFO_EHDR) << std::endl;
    std::cout << "AT_UCACHEBSIZE: " << getauxval(AT_UCACHEBSIZE) << std::endl;
    std::cout << "AT_ICACHEBSIZE: " << getauxval(AT_ICACHEBSIZE) << std::endl;
    std::cout << "AT_FPUCW: " << getauxval(AT_FPUCW) << std::endl;
}
