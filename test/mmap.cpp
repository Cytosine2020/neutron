#include <sys/mman.h>


int main() {
    mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, -1, 4096);
}
