#ifndef NEUTRON_RISCV_LINUX_GDB_HPP
#define NEUTRON_RISCV_LINUX_GDB_HPP


#include "riscv_isa_utility.hpp"

#include "riscv_linux.hpp"
#include "gdb_server.hpp"


namespace neutron {
    template<typename xlen>
    class LinuxGDBCore : public LinuxHart_<LinuxGDBCore<xlen>, xlen> {
    private:
        GDBServer gdb;

        using SuperT = LinuxHart_<LinuxGDBCore<xlen>, xlen>;

        SuperT *super() { return this; }

        LinuxGDBCore *sub_type() { return this; }

    public:
        using RetT = typename SuperT::RetT;
        using XLenT = typename SuperT::XLenT;
        using UXLenT = typename SuperT::UXLenT;
        using IntRegT = typename SuperT::IntRegT;
        using CSRRegT = typename SuperT::CSRRegT;

        LinuxGDBCore(UXLenT hart_id, LinuxProgram<xlen> &mem,
                     bool debug = false, std::ostream &debug_stream = std::cout) :
                SuperT{hart_id, mem, debug, debug_stream}, gdb{false} {}

        bool gdb_handler() {
            while (true) {
                auto message = gdb.receive();

                if (message.empty()) return false;

                switch (message.pop()) {
                    case -1:
                        neutron_unreachable("");
                    case 'c':
                        return true;
                    case 'g':
                        for (usize i = 0; i < IntRegT::INTEGER_REGISTER_NUM; ++i) {
                            if (!gdb.push_memory(sub_type()->get_x(i))) return false;
                        }

                        if (!gdb.push_memory(sub_type()->get_pc()) || !gdb.send()) return false;
                        break;
                    case 'M': {
                        auto addr = message.pop_hex<UXLenT>();
                        message.pop();
                        auto size = message.pop_hex<UXLenT>();
                        message.pop();

                        if (!addr.first || !size.first) continue;

                        std::vector<::iovec> vec{};

                        if (this->pcb.memory_get_vector(addr.second, size.second, riscv_isa::R_BIT, vec)) {
                            for (auto &item: vec) {
                                if (!message.pop_memory(static_cast<u8 *>(item.iov_base), item.iov_len)) return false;
                            }
                            if (!gdb.push_reply("OK")) return false;
                        } else {
                            if (!gdb.push_reply('E') || !gdb.push_memory<u8>(EFAULT)) return false;
                        }

                        if (!gdb.send()) return false;
                    }
                        break;
                    case 'm': {
                        auto addr = message.pop_hex<UXLenT>();
                        message.pop();
                        auto size = message.pop_hex<UXLenT>();

                        if (!addr.first || !size.first) continue;

                        std::vector<::iovec> vec{};

                        if (this->pcb.memory_get_vector(addr.second, size.second, riscv_isa::R_BIT, vec)) {
                            for (auto &item: vec) {
                                if (!gdb.push_memory(item.iov_base, item.iov_len)) return false;
                            }
                        } else {
                            if (!gdb.push_reply('E') || !gdb.push_memory<u8>(EFAULT)) return false;
                        }

                        if (!gdb.send()) return false;
                    }
                        break;
                    case 'q':
                        if (message.begin_with("Symbol::")) {
                            if (!gdb.send_reply("OK")) return false;
                        } else if (message.begin_with("Offsets")) {
                            if (!gdb.push_reply("Text=") ||
                                !gdb.push_hex(this->pcb.elf_shift) ||
                                !gdb.push_reply(";Data=") ||
                                !gdb.push_hex(this->pcb.elf_shift) ||
                                !gdb.push_reply(";Bss=") ||
                                !gdb.push_hex(this->pcb.elf_shift) ||
                                !gdb.send())
                                return false;
                        } else if (message.begin_with("Supported")) {
                            if (!gdb.send_reply("PacketSize=4096")) return false;
                        } else if (message.begin_with("Attached")) {
                            if (!gdb.send_reply("0")) return false;
                        } else {
                            if (!gdb.send_reply("")) return false;
                        }
                        break;
                    case 'v':
                        if (message.begin_with("Kill")) {
                            gdb.send_reply("OK");
                            return false;
                        } else {
                            if (!gdb.send_reply("")) return false;
                        }
                        break;
                    case '?':
                        if (!gdb.send_reply("S05")) return false;
                        break;
                    default:
                        if (!gdb.send_reply("")) return false;
                }
            }
        }

        bool gdb_break_point() {
            return gdb.get_fd() == -1 || (gdb.send_reply("S05") && gdb_handler());
        }

//        XLenT sys_writev(int fd, UXLenT iov, UXLenT iovcnt) {
//            gdb_break_point();
//            return super()->sys_writev(fd, iov, iovcnt);
//        }
//
//        XLenT sys_write(int fd, UXLenT addr, UXLenT size) {
//            gdb_break_point();
//            return super()->sys_write(fd, addr, size);
//        }

        bool break_point_handler(neutron_unused UXLenT addr) { return gdb_break_point(); }

        void start(u32 port) {
            if (!sub_type()->goto_main()) { return; }

            if (!gdb.gdb_connect(port) || !gdb_handler()) { return; }

            while (sub_type()->visit() || sub_type()->trap_handler()) {}

            gdb_break_point();
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_GDB_HPP
