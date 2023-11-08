#pragma once

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "OpenSSLWrappers.hh"

#include "Socket.hh"

class SocketTLS : public Socket {
public:
    SocketTLS(std::shared_ptr<Socket> s);
    ~SocketTLS();
    bool attemptHandshakeAsClient();
    bool checkHandshakeAsServer();
    virtual void getData(std::vector<uint8_t>& data);
    virtual std::unique_ptr<Socket> acceptConnection();
    virtual int sendData(const std::vector<uint8_t>& data);
    virtual void closeSocket();
    virtual int getFd();
private:
    SSL_CTX_Wrapper ssl_ctx_;
    SSL_Wrapper ssl_;
    std::shared_ptr<Socket> socketBase_;
    std::unique_ptr<int> x_;
};