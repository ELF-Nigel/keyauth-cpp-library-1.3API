#pragma once
#include <string>
#include <algorithm>
#include <cctype>

namespace keyauth_detail {
struct SignatureHeaders {
    std::string signature;
    std::string timestamp;
    bool conflicting = false;
};

// libcurl may deliver CONNECT, informational, final and trailer header blocks.
// Only the current response's values may authenticate its body.
inline bool consume_header(SignatureHeaders& out, std::string line) {
    if (line.rfind("HTTP/", 0) == 0) {
        out = {};
        return true;
    }
    const auto colon = line.find(':');
    if (colon == std::string::npos) return true;
    std::string key = line.substr(0, colon);
    std::transform(key.begin(), key.end(), key.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string* target = nullptr;
    if (key == "x-signature-ed25519") target = &out.signature;
    if (key == "x-signature-timestamp") target = &out.timestamp;
    if (!target) return true;
    std::string value = line.substr(colon + 1);
    const auto first = value.find_first_not_of(" \t\r\n");
    const auto last = value.find_last_not_of(" \t\r\n");
    value = first == std::string::npos ? "" : value.substr(first, last - first + 1);
    if (!target->empty() && *target != value) out.conflicting = true;
    *target = value;
    return true;
}
}
