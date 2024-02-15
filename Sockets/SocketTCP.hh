#pragma once

#include <memory>
#include <vector>
#include <stdint.h>

#include "Socket.hh"

class SocketTCP : public Socket {
public:
    SocketTCP(Socket::Type type, int port);
    virtual ~SocketTCP();
    virtual int getData(std::vector<uint8_t>& data);
    virtual void connectToServer();
    virtual std::unique_ptr<Socket> acceptClientConnection();
    virtual int sendData(const std::vector<uint8_t>& data);
    virtual void closeSocket();
    virtual int getFd();
private:
    SocketTCP(std::unique_ptr<int>&& sock);
    int port_;
    std::unique_ptr<int> sock_;
};