#include "gdb_server.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ostream>

#include "neutron_utility.hpp"


namespace neutron {
    bool GDBServer::Buffer::receive(int socket) {
        if (begin_ < end_ && begin_ > 0) {
            for (usize i = begin_; i < end_; ++i) {
                array[i - begin_] = array[i];
            }
        }

        usize remain = end_ - begin_;

        isize ret = recv(socket, array.begin() + remain, array.size() - remain, 0);

        begin_ = 0;
        end_ = remain + ret;

        if (debug) {
            if (ret > 0) {
                *debug_stream << "[receive] ";
                (*debug_stream).write(reinterpret_cast<const char *>(array.begin() + remain), end_);
                *debug_stream << std::endl;
            } else {
                *debug_stream << "recv failed!" << std::endl;
            }
        }

        return ret > 0;
    }

    bool GDBServer::Buffer::receive_message(int socket, GDBServer::Buffer &buf) {
        if (!seek_message(socket)) return false;

        u8 sum = 0;

        while (true) {
            i32 a = pop_socket(socket), b;

            switch (a) {
                case -1:
                    goto error;
                case '$':
                    if (debug) { *debug_stream << "unexpected character `$`!" << std::endl; }
                    goto error;
                case '#':
                    if (sum != pop_hex_byte_socket(socket)) { goto error; }
                    return true;
                case '}':
                    b = pop_socket(socket);
                    if (b == -1) { goto error; }
                    sum += a + b;
                    buf.push(static_cast<u8>(b) ^ ESCAPE);
                    break;
                default:
                    sum += a;
                    buf.push(a);
            }
        }

        error:
        buf.clear();
        clear();
        return false;
    }

    bool GDBServer::gdb_connect(u32 port) {
        int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in local{
                .sin_family = AF_INET,
                .sin_port = htons(port),
                .sin_addr = {.s_addr = INADDR_ANY},
                .sin_zero = {},
        };
        struct sockaddr_in gdb_addr{};
        socklen_t len = sizeof(gdb_addr);

        if (socket_fd == -1) {
            neutron_warn("socket creation failed!");
            goto error;
        }

        if (bind(socket_fd, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) == -1) {
            neutron_warn("socket bind failed!");
            goto error;
        }

        if (listen(socket_fd, 1) == -1) {
            neutron_warn("socket listen failed!");
            goto error;
        }

        gdb = ::accept(socket_fd, reinterpret_cast<struct sockaddr *>(&gdb_addr), &len);

        if (gdb == -1) {
            neutron_warn("accept failed!");
            goto error;
        }

        if (debug) {
            char *in_addr = reinterpret_cast<char *>(&gdb_addr.sin_addr);
            *debug_stream << static_cast<u32>(in_addr[0]) << '.'
                          << static_cast<u32>(in_addr[1]) << '.'
                          << static_cast<u32>(in_addr[2]) << '.'
                          << static_cast<u32>(in_addr[3]) << ':'
                          << gdb_addr.sin_port << std::endl;
        }

        close(socket_fd);

        if (recv_buffer.pop_socket(gdb) != '+') {
            if (debug) { *debug_stream << "the first character received is not `+`!" << std::endl; }
            gdb_close();
        }

        send_buffer.push('$');

        return true;

        error:
        close(socket_fd);
        return false;
    }

    bool GDBServer::send() {
        u8 sum = 0;

        for (auto *ptr = send_buffer.begin() + 1, *end = send_buffer.end(); ptr < end; ++ptr) {
            sum += *ptr;
        }

        if (!send_buffer.push('#') || !send_buffer.push_hex_byte(sum)) return false;

        for (usize retry = 0; retry < RETRY; ++retry) {
            isize byte = send_message(reinterpret_cast<const char *>(send_buffer.begin()),
                                      send_buffer.size());

            if (static_cast<usize>(byte) == send_buffer.size()) {
                recv_buffer.clear();
                if (recv_buffer.pop_socket(gdb) == '+') {
                    send_buffer.clear();
                    send_buffer.push('$');
                    return true;
                }
            }
        }

        return false;
    }
}
