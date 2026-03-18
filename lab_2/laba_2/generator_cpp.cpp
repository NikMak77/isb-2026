#include <fstream>
#include <string>
#include <random>

void generator_random(const std::string& path) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    std::string seq;
    for (int i = 0; i < 128; ++i)
        seq += std::to_string(dis(gen));
    std::ofstream file(path);
    file << seq;
}

int main() {
    generator_random("generator_cpp.txt");
}