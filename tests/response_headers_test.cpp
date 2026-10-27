#include "../response_headers.hpp"
#include <cstdlib>
#include <iostream>

static void require(bool condition) {
    if (!condition) std::abort();
}
int main() {
    keyauth_detail::SignatureHeaders h;
    using keyauth_detail::consume_header;
    consume_header(h, "HTTP/1.1 200 Connection established\r\n");
    consume_header(h, "X-Signature-Ed25519: stale\r\n");
    consume_header(h, "HTTP/2 200\r\n");
    require(h.signature.empty() && h.timestamp.empty());
    consume_header(h, "X-SIGNATURE-ED25519:\tvalid \t\r\n");
    consume_header(h, "x-signature-timestamp: 1770000000\r\n");
    require(h.signature == "valid" && h.timestamp == "1770000000");
    consume_header(h, "x-signature-ed25519: valid\r\n");
    require(!h.conflicting);
    consume_header(h, "x-signature-ed25519: other\r\n");
    require(h.conflicting);
    consume_header(h, "HTTP/1.1 103 Early Hints\r\n");
    require(!h.conflicting && h.signature.empty());
    consume_header(h, "x-signature-ed25519: interim\r\n");
    consume_header(h, "HTTP/1.1 503 Service Unavailable\r\n");
    require(h.signature.empty());
    consume_header(h, "server: edge\r\n");
    consume_header(h, "\r\n");
    require(h.signature.empty());
    std::cout << "Response header regression tests passed\n";
}
