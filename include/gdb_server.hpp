#ifndef NEUTRON_GDB_SERVER_HPP
#define NEUTRON_GDB_SERVER_HPP

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ostream>

#include "neutron_utility.hpp"


namespace neutron {
    class GDBServer {
    private:
        static constexpr usize BUF_SIZE = 4096;
        static constexpr usize RETRY = 4;
        static constexpr u8 ESCAPE = 0x20;

        class Buffer {
        private:
            Array<u8> array;
            usize begin_;
            usize end_;
            bool debug;
            std::ostream *debug_stream;

            static i32 char_to_u8(char c) {
                if ('0' <= c && c <= '9') { return c - '0'; }
                if ('a' <= c && c <= 'f') { return c - 'a' + 10; }
                if ('A' <= c && c <= 'F') { return c - 'A' + 10; }
                return -1;
            }

            static u8 u8_to_char(u8 c) {
                if (c <= 9) { return c + '0'; }
                if (10 <= c && c <= 15) { return c - 10 + 'a'; }
                neutron_unreachable("");
            }

        public:
            explicit Buffer(usize size, bool debug = false, std::ostream *debug_stream = &std::cerr) :
                    array{size}, begin_{0}, end_{0}, debug{debug}, debug_stream{debug_stream} {}

            Buffer(Buffer &&other) noexcept = default;

            Buffer &operator=(Buffer &&other) noexcept = default;

            u8 &operator[](usize index) { return array[begin_ + index]; }

            const u8 &operator[](usize index) const { return array[begin_ + index]; }

            usize size() const { return end_ - begin_; }

            bool empty() const { return size() == 0; }

            u8 *begin() { return array.begin() + begin_; }

            u8 *end() { return array.begin() + end_; }

            const u8 *begin() const { return array.begin() + begin_; }

            const u8 *end() const { return array.begin() + end_; }

            void clear() {
                begin_ = 0;
                end_ = 0;
            }

            i32 pop_socket(int socket) {
                if (begin_ >= end_) {
                    if (!receive(socket)) return -1;
                }
                u8 ret = *begin();
                ++begin_;
                return ret;
            }

            i32 pop() {
                if (begin_ >= end_) { return -1; }
                u8 ret = *begin();
                ++begin_;
                return ret;
            }

            i32 pop_hex_byte_socket(int socket) {
                i32 a = char_to_u8(pop_socket(socket));
                i32 b = char_to_u8(pop_socket(socket));

                if (a == -1 || b == -1) { return -1; }

                return (static_cast<u32>(a) << 4u) + b;
            }

            i32 pop_hex_byte() {
                i32 a = char_to_u8(pop());
                i32 b = char_to_u8(pop());

                if (a == -1 || b == -1) { return -1; }

                return (static_cast<u32>(a) << 4u) + b;
            }

            template<typename T>
            std::pair<bool, T> pop_hex() {
                T ret = 0;

                usize i = 0;
                for (; size() > 0 && i < sizeof(T) * 2; ++i) {
                    i32 tmp = char_to_u8(*begin());
                    if (tmp == -1) { break; }
                    pop();
                    ret *= 16;
                    ret += tmp;
                }

                return i == 0 ? std::make_pair(false, T{}) : std::make_pair(true, T{ret});
            }

            bool push(u8 item) {
                if (end_ < array.size()) {
                    *end() = item;
                    ++end_;
                    return true;
                } else {
                    return false;
                }
            }

            bool push_memory(const u8 *src, usize size) {
                for (usize i = 0; i < size; ++i) {
                    if (!push_hex_byte(src[i])) return false;
                }

                return true;
            }

            bool pop_memory(u8 *src, usize size) {
                for (usize i = 0; i < size; ++i) {
                    i32 item = pop_hex_byte();
                    if (item == -1) return false;
                    src[i] = item;
                }

                return true;
            }

            i32 push_hex_byte(u8 byte) {
                return push(u8_to_char(byte >> 4u)) && push(u8_to_char(byte & 0b1111u));
            }

            bool receive(int socket);

            bool seek_message(int socket) {
                while (true) {
                    switch (pop_socket(socket)) {
                        case -1:
                            return false;
                        case '}':
                            if (pop_socket(socket) == -1) return false;
                            break;
                        case '$':
                            return true;
                    }
                }
            }

            bool receive_message(int socket, Buffer &buf);

            bool begin_with(const char *other) {
                for (const u8 *a = begin(), *b = reinterpret_cast<const u8 *>(other);
                     a < end() && *b != '\0'; ++a, ++b) {
                    if (*a != *b) { return false; }
                }
                return true;
            }

            ~Buffer() = default;
        };

        Buffer recv_buffer, send_buffer;
        int gdb;
        bool debug;
        std::ostream *debug_stream;

        isize send_message(const char *buf, usize size) {
            isize ret = ::send(gdb, buf, size, 0);

            if (ret == -1) {
                gdb_close();

                if (debug) { *debug_stream << "send failed!" << std::endl; }

                return -1;
            }

            if (debug) {
                *debug_stream << "[sent   ] ";
                (*debug_stream).write(buf, size);
                *debug_stream << std::endl;
            }

            return ret;
        }

        void gdb_close() {
            if (gdb != -1) { close(gdb); }
            gdb = -1;
        }

    public:
        explicit GDBServer(bool debug = false, std::ostream &debug_stream = std::cerr) :
                recv_buffer{BUF_SIZE, debug, &debug_stream},
                send_buffer{BUF_SIZE, debug, &debug_stream},
                gdb{-1}, debug{debug}, debug_stream{&debug_stream} {}

        bool gdb_connect(u32 port);

        GDBServer(GDBServer &&other) noexcept:
                recv_buffer{std::move(other.recv_buffer)}, send_buffer{std::move(other.send_buffer)},
                gdb{other.gdb}, debug{other.debug}, debug_stream{other.debug_stream} {
            other.gdb = -1;
        }

        GDBServer &operator=(GDBServer &&other) noexcept {
            if (this != &other) {
                if (this->gdb != -1) { close(this->gdb); }
                this->recv_buffer = std::move(other.recv_buffer);
                this->gdb = other.gdb;
                this->debug = other.debug;
                this->debug_stream = other.debug_stream;
                other.gdb = -1;
            }

            return *this;
        }

        int get_fd() const { return gdb; }

        Buffer receive() {
            Buffer buf{BUF_SIZE};

            for (usize retry = 0; retry < RETRY; ++retry) {
                if (recv_buffer.receive_message(gdb, buf)) {
                    send_message("+", 1);
                    return buf;
                } else {
                    send_message("-", 1);
                }
            }

            gdb_close();
            return buf;
        }

        bool push_reply(u8 item) {
            switch (item) {
                case '$':
                case '#':
                case '}':
                case '*':
                    if (!send_buffer.push('}') || !send_buffer.push(item ^ ESCAPE)) return false;
                    break;
                default:
                    if (!send_buffer.push(item)) return false;
            }
            return true;
        }

        template<typename T>
        bool push_hex(T obj) {
            for (isize i = sizeof(T) - 1; i >= 0; --i) {
                if (!send_buffer.push_hex_byte(reinterpret_cast<const u8 *>(&obj)[i])) { return false; }
            }
            return true;
        }

        bool push_reply(const char *msg) {
            for (usize i = 0; msg[i] != '\0'; ++i) { if (!push_reply(msg[i])) { return false; }}
            return true;
        }

        bool push_memory(const void *src, usize size) {
            return send_buffer.push_memory(reinterpret_cast<const u8 *>(src), size);
        }

        bool pop_memory(void *src, usize size) {
            return recv_buffer.pop_memory(reinterpret_cast<u8 *>(src), size);
        }

        template<typename T>
        bool push_memory(T obj) { return push_memory(&obj, sizeof(obj)); }

        bool send();

        bool send_reply(const char *msg) { return push_reply(msg) && send(); }

        ~GDBServer() {
            if (gdb != -1) { close(gdb); }
        }
    };
}


#endif //NEUTRON_GDB_SERVER_HPP
