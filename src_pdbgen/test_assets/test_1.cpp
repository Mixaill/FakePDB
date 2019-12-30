#include <iostream>

float a(int a) {
    return a*2.5;
}

int b(float a, int b) {
    return a * b / 3;
}

int main()
{
    std::cout << a(1) + b(2, 5) << std::endl;
}
