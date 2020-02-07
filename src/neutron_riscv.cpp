#include <iostream>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "target/hart.hpp"
#include "target/dump.hpp"

using namespace riscv_isa;

#include "elf_header.hpp"

using namespace elf;


class LinuxHart : public Hart<LinuxHart> {
public:
    LinuxHart(XLenT pc, IntegerRegister<> &reg, Memory<> &mem) : Hart{pc, reg, mem} {}

    void start() {
        while (true) {
            Instruction *inst = mem.address<Instruction>(get_pc());

            switch (inst == nullptr ? MEMORY_ERROR : visit(inst)) {
                case ILLEGAL_INSTRUCTION_EXCEPTION:
                    if (inst == nullptr)
                        riscv_isa_unreachable("illegal instruction exception instruction fetch failed!");

                    std::cerr << "Illegal instruction at " << std::hex << get_pc() << ' ' << *inst << std::endl;

                    return;
                case MEMORY_ERROR:
                    std::cerr << "Memory error at " << std::hex << get_pc() << std::endl;

                    return;
                case INSTRUCTION_ADDRESS_MISALIGNED_EXCEPTION:
                    std::cerr << "Instruction address misaligned at " << std::hex << get_pc() << ' '
                              << *reinterpret_cast<u32 *>(inst) << std::endl;

                    return;
                case ECALL:
                    switch (int_reg.get_x(IntegerRegister<>::A7)) {
                        case 57: {
                            int fd = int_reg.get_x(IntegerRegister<>::A0);
                            int_reg.set_x(IntegerRegister<>::A0, fd > 2 ? close(fd) : 0); // todo: stdin, stdout, stderr

                            break;
                        }
                        case 64:
                            int_reg.set_x(IntegerRegister<>::A0, write(int_reg.get_x(IntegerRegister<>::A0),
                                                                       mem.address<char>(
                                                                               int_reg.get_x(IntegerRegister<>::A1)),
                                                                       IntegerRegister<>::A3));

                            break;
                        case 80:
                            int_reg.set_x(IntegerRegister<>::A0, -1); // todo: need convert

                            break;
                        case 93:
                            std::cout << std::endl << "[exit " << int_reg.get_x(IntegerRegister<>::A0) << ']'
                                      << std::endl;

                            return;
                        case 214:

                            break;
                        default:
                            std::cerr << "Invalid ecall number at " << std::hex << get_pc()
                                      << ", call number " << std::dec << int_reg.get_x(IntegerRegister<>::A7)
                                      << std::endl;

                            return;
                    }
                    inc_pc(ECALLInst::INST_WIDTH);

                    break;
                case EBREAK:
                    inc_pc(ECALLInst::INST_WIDTH);

                    break;
                default:;
            }
        }
    }
};


int main(int argc, char **argv) {
    if (argc != 2) riscv_isa_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) riscv_isa_abort("open file failed!");

    struct stat file_stat{};
    if (fstat(fd, &file_stat) != 0) riscv_isa_abort("fstat file failed!");
    usize size = file_stat.st_size;

    void *file = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (file == MAP_FAILED) riscv_isa_abort("Memory mapped io failed!");

    if (close(fd) != 0) riscv_isa_abort("Close file failed!");

    MappedFileVisitor visitor{file, size};

    auto *elf_header = ELF32Header::read(visitor);
    if (elf_header == nullptr) riscv_isa_abort("Incompatible format or broken file!");
    if (elf_header->file_type != ELF32Header::EXECUTABLE) riscv_isa_abort("Not an executable file!");

//    std::cout << *elf_header << std::endl;

    auto *section_header_string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(
            &elf_header->sections(visitor)[elf_header->string_table_index], visitor);
    if (section_header_string_table_header == nullptr) riscv_isa_abort("Broken section header string table!");
//    auto section_header_string_table = section_header_string_table_header->get_string_table(visitor);

    IntegerRegister<> reg{};
    reg.set_x(IntegerRegister<>::SP, 0xfffff000);

    Memory<> mem{0x100000000};

    for (auto &program: elf_header->programs(visitor)) {
//        std::cout << program << std::endl;

        if (program.type == ELF32ProgramHeader::LOADABLE)
            mem.memory_copy(program.virtual_address, static_cast<u8 *>(file) + program.offset, program.file_size);
    }

//    ELF32StringTableHeader *string_table_header = nullptr;
//
//    for (auto &section: elf_header->sections(visitor)) {
//        char *name = section_header_string_table.get_str(section.name);
//        if (name == nullptr) riscv_isa_abort("Broken section header string table!");
//        std::cout << section_header_string_table.get_str(section.name) << ": " << section.section_type
//                  << ", " << section.size << std::endl;
//
//        if (strcmp(name, ".strtab") == 0) {
//            if (string_table_header != nullptr) riscv_isa_abort("Multiple string table!");
//            string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(&section, visitor);
//            if (string_table_header == nullptr) riscv_isa_abort("Broken string table!");
//        }
//    }
//
//    if (string_table_header == nullptr) riscv_isa_abort("No string table!");
//    auto shared_string_table = string_table_header->get_string_table(visitor);
//
//    for (auto &section: elf_header->sections(visitor)) {
//        auto *symbol_table_header = ELF32SectionHeader::cast<ELF32SymbolTableHeader>(&section, visitor);
//        if (symbol_table_header != nullptr) {
//            for (auto &symbol: symbol_table_header->get_symbol_table(visitor)) {
//                const char *name = symbol.name == 0 ? "[no name]" : shared_string_table.get_str(symbol.name);
//                if (name == nullptr) riscv_isa_abort("Broken string table!");
//                std::cout << symbol.get_type() << '\t' << symbol.get_bind() << '\t' << symbol.get_visibility()
//                          << '\t' << name << std::endl;
//            }
//        }
//    }

    LinuxHart core{static_cast<xlen_trait::XLenT>(elf_header->entry_point), reg, mem};
    core.start();
}
