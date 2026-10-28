# keyauth-cpp-library : Please star 🌟
KeyAuth C++ Library

This is the source code of the library_x64.lib file from https://github.com/KeyAuth/KeyAuth-CPP-Example

Multi Support : x86/x64

## **Bugs**

If you are using our example with no significant changes, and you are having problems, please Report Bug here https://keyauth.fdback.io

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

## Security and API compatibility

The SDK retains the API 1.3 endpoint, TLS hostname/certificate verification,
Ed25519 response verification, a 120 second signed timestamp window, and server
session/blacklist checks. It does not automatically replace signing keys or pins.
Compare upstream changes before rebuilding and distributing a new library.

Removed runtime enforcement: raw disk-versus-loaded PE comparisons, instruction
pattern scanning, process ACL changes, repeated exception handlers, file/registry/
atom markers, module-signature heuristics, and wall-clock tamper timers. These
can reject legitimate Windows relocation, instrumentation, restricted accounts,
slow initialization, and sleep/resume. They are not reliable evidence that a user
has bypassed authentication. Server authentication and signed responses remain
mandatory for normal API operations. Client-side code can still be patched by a
person controlling the device; sensitive authorization must be enforced server-side.

The SDK checks HTTP status before checking signature headers, never automatically
replays state-changing requests, and allows normal CDN DNS rotation. It rejects
missing/invalid authentication signatures, conflicting signature headers and
expired signed responses. The file endpoint retains upstream compatibility:
downloads with neither signature header rely on verified HTTPS; partial or invalid
signatures are rejected. Validate publisher signatures or an independently trusted
digest before executing downloaded content.

API fields are individually URL encoded. Executable/token checksums use Windows
cryptography rather than command shells. MD5 is used only for the existing API
checksum fields; it is not an authentication primitive. Debug logging omits bodies.

## Handling errors

Network, HTTP and signature failures now throw `KeyAuth::request_error` rather
than terminating the host process. Unexpected signed response schemas may throw
JSON exceptions. Catch exceptions at your application's API boundary and keep
protected features unavailable when the operation fails:

```cpp
try {
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success) return 1;
    KeyAuthApp.license("your_license_key");
    if (!KeyAuthApp.response.success) return 1;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
```

An HTTP 429/5xx, gateway/proxy page, or unsigned HTTP success is a failed request,
not proof of user tampering. Do not remove signature validation to work around it.
For timestamp failures, synchronize Windows time. A missing header cannot be
reconstructed by the client; investigate the API/intermediary and sanitized logs.

## Threads and lifetime

API operations are serialized per instance, including heartbeat calls. Initialization
and login state belong to the instance. The owned heartbeat stops on destruction;
network errors do not assert a ban. Stop the optional ban monitor before shutdown.
Do not destroy an API instance from its monitor callback, concurrently destroy it
while another thread calls it, or directly read/write public fields concurrently
with background work. Configure hosts/pins before starting API activity.

The `require_pinning` flag now requires a configured pin. Multiple `sha256//` pins
can support an approved key rotation. TLS certificate/hostname verification stays
enabled alongside pins. `block_private_dns` checks the connected private address;
the legacy `block_custom_ca` field is not an implemented trust-store policy.

## String visibility and version tags

The hardcoded internal build tag has been removed. This does not prevent version
fingerprinting or reverse engineering. `enable_secure_strings()` is optional XOR
obfuscation of selected runtime configuration fields, not encryption or a place to
store secrets. Windows imports such as `Sleep` and public API identifiers are not
secrets. No import hiding, packer or anti-analysis mechanism is added by this patch.

## Build and regression tests

Rebuild applications against the updated headers and library together; the private
instance layout changed. From a Visual Studio x64 developer prompt:

```bat
msbuild library.vcxproj /p:Configuration=Release /p:Platform=x64
```

The existing CI workflow runs embedded regression checks for HTTP header block isolation and duplicates, valid/tampered/expired
Ed25519 messages, milliseconds timestamps, binary bodies, checksum vectors, malformed
JSON handling and API object lifetime. They do not replace live application testing.


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

## Live ban monitor (threaded)

Optional background check that polls every 45 seconds. Always stop it before exiting.

```cpp
KeyAuthApp.start_ban_monitor(45, false, [] {
    std::cout << "Blacklisted, exiting..." << std::endl;
    exit(0);
});

// later, before exit
KeyAuthApp.stop_ban_monitor();
```
