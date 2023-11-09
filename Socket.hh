#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <stdint.h>

class Socket {
public:
    enum class Type { SERVER, CLIENT};
    Socket(Type type);
    Socket(const Socket& s);
    virtual void getData(std::vector<uint8_t>& data) = 0;
    virtual void connectToServer() = 0;
    virtual std::unique_ptr<Socket> acceptClientConnection() = 0;
    virtual int sendData(const std::vector<uint8_t>& data) = 0;
    virtual void closeSocket() = 0;
    virtual int getFd() = 0;
    virtual bool attemptHandshakeAsClient();
    virtual bool checkHandshakeAsServer();
protected:
    Type type_;
};