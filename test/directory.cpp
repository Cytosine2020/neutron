#include <unistd.h>
#include <iostream>

int main() {
    char *name = get_current_dir_name();

    std::cout << name << std::endl;

}
