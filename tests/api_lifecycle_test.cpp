#include "auth.hpp"
#include <iostream>
extern std::string curl_escape(CURL*, const std::string&);
extern std::string get_str_between_two_str(const std::string&, const std::string&, const std::string&);
int main() {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    const auto hwid = utils::get_hwid();
    if (hwid.rfind("S-1-", 0) != 0 || utils::get_hwid() != hwid) return 1;
    if (curl_escape(nullptr, "a&+= %") != "a%26%2B%3D%20%25") return 1;
    if (get_str_between_two_str("?user=test&token=abc", "&token=", "") != "abc") return 1;
    for (int i = 0; i < 10; ++i) {
        KeyAuth::api first("first", "1234567890", "1.0", "https://keyauth.win/api/1.3/", "");
        KeyAuth::api second("second", "0987654321", "1.0", "https://keyauth.win/api/1.3/", "");
        first.enable_secure_strings();
        if (!first.name.empty()) return 1;
        first.enable_secure_strings(false);
        if (first.name != "first" || second.name != "second") return 1;
        first.stop_ban_monitor();
    }
    std::cout << "API lifecycle and form encoding regression tests passed\n";
}
