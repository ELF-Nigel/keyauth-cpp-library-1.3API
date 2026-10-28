#include "utils.hpp"

#include <windows.h>
#include <sddl.h>
#include <vector>
#pragma comment(lib, "advapi32.lib")

std::string utils::get_hwid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "none";
    struct TokenOwner {
        HANDLE handle;
        ~TokenOwner() { CloseHandle(handle); }
    } owner{token};
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (!needed) return "none";
    std::vector<unsigned char> buffer(needed);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) return "none";
    char* sid = nullptr;
    if (!ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid))
        return "none";
    struct SidOwner {
        char* value;
        ~SidOwner() { LocalFree(value); }
    } sid_owner{sid};
    return std::string(sid);
}

std::time_t utils::string_to_timet(std::string timestamp) {
	char* end = nullptr;
	auto cv = strtol(timestamp.c_str(), &end, 10);
	if (end == timestamp.c_str())
		return 0;
	return static_cast<time_t>(cv);
}

std::tm utils::timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
