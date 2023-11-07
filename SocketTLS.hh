#pragma once

#include <memory>

#include "Socket.hh"

class SocketTLS : public Socket {
public:
    SocketTLS(Socket s);
private:
    SSL *ssl;
    std::unique_ptr<int> x_;
};