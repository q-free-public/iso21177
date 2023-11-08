#pragma once

#include <memory>
#include "Socket.hh"

extern "C" {
    #include <openssl/ssl.h>
}

class SSL_CTX_Wrapper {
public:
    SSL_CTX_Wrapper(Socket::Type);
    SSL_CTX* operator*() {
        return _ptr.get();
    }

private:
    std::shared_ptr<SSL_CTX> _ptr;
};

class SSL_Wrapper {
public:
    SSL_Wrapper(SSL_CTX_Wrapper& ctx)
    : _ptr(SSL_new(*ctx), SSL_free) {
    }
    SSL_Wrapper()
    : _ptr() {
    }
    SSL* operator*() {
        return _ptr.get();
    }

private:
    std::shared_ptr<SSL> _ptr;
};