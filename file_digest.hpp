#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <stdexcept>
#include <string>
#pragma comment(lib, "bcrypt.lib")

namespace keyauth_detail {
// MD5 is retained solely for the API's existing executable/token hash fields.
// Authentication is provided by TLS and Ed25519, not this compatibility digest.
inline std::string file_md5(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open file for API checksum.");
    struct Provider {
        BCRYPT_ALG_HANDLE handle = nullptr;
        ~Provider() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    } provider;
    struct Hash {
        BCRYPT_HASH_HANDLE handle = nullptr;
        ~Hash() { if (handle) BCryptDestroyHash(handle); }
    } hash;
    if (BCryptOpenAlgorithmProvider(&provider.handle, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(provider.handle, &hash.handle, nullptr, 0, nullptr, 0, 0) < 0)
        throw std::runtime_error("Cannot initialize API checksum.");
    std::array<unsigned char, 16384> buffer{};
    while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || input.gcount()) {
        if (BCryptHashData(hash.handle, buffer.data(), static_cast<ULONG>(input.gcount()), 0) < 0)
            throw std::runtime_error("Cannot hash API checksum input.");
    }
    if (!input.eof()) throw std::runtime_error("Cannot read API checksum input.");
    std::array<unsigned char, 16> digest{};
    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("Cannot finish API checksum.");
    const char* hex = "0123456789abcdef";
    std::string out;
    for (const auto value : digest) {
        out += hex[value >> 4]; out += hex[value & 15];
    }
    return out;
}
}
