#include "OpenSSLWrappers.hh"

extern "C" {
    #include <openssl/ssl.h>
    #include <openssl/err.h>
}

#include <stdexcept>

SSL_CTX_Wrapper::SSL_CTX_Wrapper(Socket::Type type)
: _ptr(SSL_CTX_new(type == Socket::Type::SERVER ? TLS_server_method() : TLS_client_method()), SSL_CTX_free) {
    if (!SSL_CTX_set_min_proto_version(_ptr.get(), TLS1_3_VERSION)) {
        fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_set_min_proto_version failed");
    }
    if (1 != SSL_CTX_load_verify_locations(_ptr.get(), "ca.cert.pem", NULL)) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed: ");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    SSL_CTX_set_verify(_ptr.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}
