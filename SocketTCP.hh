#pragma once

#include <memory>
#include <vector>
#include <stdint.h>

#include "Socket.hh"

class SocketTCP : public Socket {
public:
    SocketTCP(Socket::Type type, int port);
    ~SocketTCP();
    virtual void getData(std::vector<uint8_t>& data);
    virtual std::unique_ptr<Socket> acceptConnection();
    virtual int sendData(const std::vector<uint8_t>& data);
    virtual void closeSocket();
    virtual int getFd();
private:
    SocketTCP(std::unique_ptr<int>&& sock);
    std::unique_ptr<int> sock_;
};