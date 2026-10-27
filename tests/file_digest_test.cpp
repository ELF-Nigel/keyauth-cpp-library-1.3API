#include "../file_digest.hpp"
#include <iostream>
int main() {
    const auto path = std::filesystem::temp_directory_path() / "keyauth-checksum-test.bin";
    { std::ofstream out(path, std::ios::binary); out << "abc"; }
    const auto digest = keyauth_detail::file_md5(path);
    std::filesystem::remove(path);
    if (digest != "900150983cd24fb0d6963f7d28e17f72") return 1;
    bool rejected = false;
    try { keyauth_detail::file_md5(path); } catch (const std::runtime_error&) { rejected = true; }
    if (!rejected) return 1;
    std::cout << "File checksum regression tests passed\n";
}
