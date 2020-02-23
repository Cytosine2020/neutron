#include <iostream>

void fn_0() {
    std::cout << "0" << std::endl;
}

void fn_1() {
    std::cout << "1" << std::endl;
}

void (*fn[2])() = {&fn_0, &fn_1};

int main() {
    int flag = 0;
    std::cin >> flag;

    flag = flag > 1 ? 1 : flag;

    fn[flag]();
}
