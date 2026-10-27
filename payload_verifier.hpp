#pragma once
#include <sodium.h>
#include <string>
#include <algorithm>
#include <cstdlib>

namespace keyauth_detail {
enum class PayloadResult { valid, timestamp_format, timestamp_skew, sodium_init,
                           signature_format, public_key_format, invalid_signature };
inline PayloadResult verify_payload(const std::string& signature,
    const std::string& timestamp, const std::string& body,
    const std::string& public_key, long long now_seconds) {
    if ((timestamp.size() != 10 && timestamp.size() != 13) ||
        !std::all_of(timestamp.begin(), timestamp.end(),
                     [](unsigned char c) { return c >= '0' && c <= '9'; }))
        return PayloadResult::timestamp_format;
    long long seconds = std::stoll(timestamp);
    if (timestamp.size() == 13) seconds /= 1000;
    if (std::llabs(now_seconds - seconds) > 120) return PayloadResult::timestamp_skew;
    if (sodium_init() < 0) return PayloadResult::sodium_init;
    unsigned char sig[crypto_sign_BYTES] = {};
    unsigned char pk[crypto_sign_PUBLICKEYBYTES] = {};
    size_t size = 0;
    if (signature.size() != sizeof(sig) * 2 ||
        sodium_hex2bin(sig, sizeof(sig), signature.data(), signature.size(),
                       nullptr, &size, nullptr) != 0 || size != sizeof(sig))
        return PayloadResult::signature_format;
    if (public_key.size() != sizeof(pk) * 2 ||
        sodium_hex2bin(pk, sizeof(pk), public_key.data(), public_key.size(),
                       nullptr, &size, nullptr) != 0 || size != sizeof(pk))
        return PayloadResult::public_key_format;
    const std::string message = timestamp + body;
    return crypto_sign_verify_detached(sig,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(), pk) == 0
        ? PayloadResult::valid : PayloadResult::invalid_signature;
}
}
