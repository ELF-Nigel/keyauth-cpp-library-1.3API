# keyauth-cpp-library : Please star 🌟
KeyAuth C++ Library

This is the source code of the library_x64.lib file from https://github.com/KeyAuth/KeyAuth-CPP-Example

Multi Support : x86/x64

## **Bugs**

If you are using our example with no significant changes, and you are having problems, please Report Bug here https://keyauth.cc/app/?page=forms

However, we do **NOT** provide support for adding KeyAuth to your project. If you can't figure this out you should use Google or YouTube to learn more about the programming language you want to sell a program in.

## Different Architectures
x86 :

1- Compile libcurl can be downloaded from curl.se and compiled by x86 Native Tools (Visual Studio Tools)

2- Lib Configuration -> General -> C++ Language Standard ->  ISO C++17 Standard (/std:c++17)

3- Lib Configuration -> Advanced -> Character Set ->  Multi-Byte Character Set

4- Lib Configuration -> Preprocessor definiton for CURL -> CURL_STATICLIB

## **Using The Library**
This section covers a minimal, working integration with the headers in this repo.

1. Add the library headers and sources to your project (or build the `.lib` from this repo).
2. Include `auth.hpp` in your project file.
3. Initialize the API once at startup, then call login/license/upgrade as needed.
4. Keep your build settings on C++17 and link with the same libraries as this repo.

Minimal example:
```cpp
#include "auth.hpp"

using namespace KeyAuth;

std::string name = "your_app_name";
std::string ownerid = "your_owner_id";
std::string version = "1.0";
std::string url = "https://keyauth.win/api/1.3/";
std::string path = ""; // optional

api KeyAuthApp(name, ownerid, version, url, path);

int main() {
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success) {
        return 1;
    }
    KeyAuthApp.license("your_license_key");
    if (!KeyAuthApp.response.success) {
        return 1;
    }
    return 0;
}
```

Notes:
1. If you are using the KeyAuth examples, keep their integrity/session checks intact.
2. Use the same `CURL_STATICLIB` define as shown above when statically linking.
3. Rebuild the library after pulling updates to keep everything in sync.

## **Security Features (Built-In)**
The library ships with security checks enabled by default. You do not need to manually call anything beyond `init()` and a normal login/license call.

What runs automatically:
1. **Integrity checks** (prologue snapshots, function region validation, `.text` hashing, page protections).
2. **Module checks** (core module signature verification + RWX section detection).
3. **Hosts-file checks** for API host tampering.
4. **Timing anomaly checks** to detect time tamper.
5. **Session heartbeat** after successful login/license/upgrade/web login.

How to keep security enabled:
1. Always call `KeyAuthApp.init()` once before any other API call.
2. Do not remove the built-in checks or tamper with the library internals.
3. Keep your application linked against the updated library after pulling changes.

How to verify it is running:
1. Use the library normally — the checks are automatic.
2. If a check fails, the library will fail closed with an error message.

## **Optional Hardening Ideas (Not Enabled)**
These are intentionally **not** enabled in the library to avoid false positives, but you can add them if your app needs them.

1. **PE header erase**: wipe PE header pages after load to make casual dumping harder. This is not a check; it simply reduces dump quality.
2. **Module allowlists**: require a strict set of loaded modules; this breaks overlays and many legitimate plugins.
3. **System module path checks**: enforce System32/SysWOW64-only paths; can fail on custom Windows installs.
4. **Hypervisor detection**: block VMs; useful for niche threat models but unfriendly to legit users.
5. **VirtualProtect IAT validation**: detect IAT hooks; can false-positive in some environments.

## **Security Troubleshooting**
If you see security failures, common causes include:
1. **Modified system DLLs**: non‑Microsoft versions or patched DLLs will be rejected.
2. **Time tampering**: manual clock changes or large time skew can trigger timing checks.
3. **Patched binaries**: inline hooks/NOP patches or modified `.text` will fail integrity checks.

## **Changelog (Overhaul Summary)**
This list summarizes all changes made in the overhaul:
1. **Integrity checks**: prologue snapshots, function region validation, detour detection, `.text` slice hashing, page protections.
2. **Module trust**: Microsoft signature verification for core DLLs, RWX section detection.
3. **Timing checks**: timing anomaly detection to catch clock tamper.
4. **Import checks**: import address validation.
5. **Network hardening**: hosts‑file override detection for API host.
6. **Session hardening**: session heartbeat after successful login/license/upgrade/web login.
7. **DLL search order**: hardened DLL lookup and removed current‑dir hijacking.
8. **String exposure**: request data zeroized after use; sensitive parameters wiped via `ScopeWipe`.
9. **Debug logging**: minimized request/URL logging to reduce in‑memory exposure.
10. **Parsing hardening**: safer JSON parsing and substring handling to avoid crashes.
11. **Curl safety**: fixed cleanup issues; enforced static libcurl linkage.
12. **Module path APIs**: removed hardcoded System32 paths (uses `GetSystemDirectoryW`).
13. **Example/docs**: added usage section, security feature docs, and troubleshooting guidance.

Helpful references (copy and paste into your browser):
```
https://github.com/KeyAuth/KeyAuth-CPP-Example
https://keyauth.cc/app/
https://keyauth.cc/app/?page=forms
```

## **What is KeyAuth?**

KeyAuth is a powerful cloud-based authentication system designed to protect your software from piracy and unauthorized access. With KeyAuth, you can implement secure licensing, user management, and subscription systems in minutes. Client SDKs available for [C#](https://github.com/KeyAuth/KeyAuth-CSHARP-Example), [C++](https://github.com/KeyAuth/KeyAuth-CPP-Example), [Python](https://github.com/KeyAuth/KeyAuth-Python-Example), [Java](https://github.com/KeyAuth-Archive/KeyAuth-JAVA-api), [JavaScript](https://github.com/mazkdevf/KeyAuth-JS-Example), [VB.NET](https://github.com/KeyAuth/KeyAuth-VB-Example), [PHP](https://github.com/KeyAuth/KeyAuth-PHP-Example), [Rust](https://github.com/KeyAuth/KeyAuth-Rust-Example), [Go](https://github.com/mazkdevf/KeyAuth-Go-Example), [Lua](https://github.com/mazkdevf/KeyAuth-Lua-Examples), [Ruby](https://github.com/mazkdevf/KeyAuth-Ruby-Example), and [Perl](https://github.com/mazkdevf/KeyAuth-Perl-Example). KeyAuth has several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion. Feel free to join https://t.me/keyauth if you have questions or suggestions.

> [!TIP]
> https://vaultcord.com FREE Discord bot to Backup server, members, channels, messages & more. Custom verify page, block alt accounts, VPNs & more.

## Copyright License

KeyAuth is licensed under **Elastic License 2.0**

* You may not provide the software to third parties as a hosted or managed
service, where the service provides users with access to any substantial set of
the features or functionality of the software.

* You may not move, change, disable, or circumvent the license key functionality
in the software, and you may not remove or obscure any functionality in the
software that is protected by the license key.

* You may not alter, remove, or obscure any licensing, copyright, or other notices
of the licensor in the software. Any use of the licensor’s trademarks is subject
to applicable law.

Thank you for your compliance, we work hard on the development of KeyAuth and do not appreciate our copyright being infringed.
