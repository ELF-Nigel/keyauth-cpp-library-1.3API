#include "nlohmann/json.hpp"
#include <cstdlib>
#include <iostream>
int main() {
    bool parse_error = false, type_error = false;
    try { nlohmann::json::parse("{broken"); }
    catch (const nlohmann::json::parse_error&) { parse_error = true; }
    try { nlohmann::json("not a boolean").get<bool>(); }
    catch (const nlohmann::json::type_error&) { type_error = true; }
    if (!parse_error || !type_error) return 1;
    if (!nlohmann::json::parse("{broken", nullptr, false).is_discarded()) return 1;
    std::cout << "JSON error handling regression tests passed\n";
}
