#define SODIUM_STATIC
#include "../payload_verifier.hpp"
#include <iostream>

static void require(bool condition) { if (!condition) std::abort(); }
static std::string hex(const unsigned char* bytes, size_t size) {
    std::string out(size * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), bytes, size);
    out.pop_back();
    return out;
}
int main() {
    using namespace keyauth_detail;
    require(sodium_init() >= 0);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    const auto key = hex(pk, sizeof(pk));
    const std::string body("{\"success\":true}\0tail", 21);
    auto sign = [&](const std::string& timestamp) {
        const std::string message = timestamp + body;
        unsigned char sig[crypto_sign_BYTES];
        crypto_sign_detached(sig, nullptr,
            reinterpret_cast<const unsigned char*>(message.data()), message.size(), sk);
        return hex(sig, sizeof(sig));
    };
    const std::string timestamp = "1770000000";
    const auto signature = sign(timestamp);
    require(verify_payload(signature, timestamp, body, key, 1770000000) == PayloadResult::valid);
    require(verify_payload(signature, timestamp, body + "!", key, 1770000000) == PayloadResult::invalid_signature);
    require(verify_payload(signature, timestamp, body, key, 1770000121) == PayloadResult::timestamp_skew);
    require(verify_payload(signature, timestamp, body, key, 1769999879) == PayloadResult::timestamp_skew);
    require(verify_payload(signature, timestamp, body, key, 1770000120) == PayloadResult::valid);
    require(verify_payload(sign("1770000000123"), "1770000000123", body, key, 1770000000) == PayloadResult::valid);
    require(verify_payload(signature, "1770000000x", body, key, 1770000000) == PayloadResult::timestamp_format);
    require(verify_payload("", timestamp, body, key, 1770000000) == PayloadResult::signature_format);
    require(verify_payload(signature, timestamp, body, "00", 1770000000) == PayloadResult::public_key_format);
    auto damaged = signature; damaged[0] = damaged[0] == '0' ? '1' : '0';
    require(verify_payload(damaged, timestamp, body, key, 1770000000) == PayloadResult::invalid_signature);
    sodium_memzero(sk, sizeof(sk));
    std::cout << "Payload signature regression tests passed\n";
}
