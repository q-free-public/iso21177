#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <stdint.h>

class Socket {
public:
    enum class Type { SERVER, CLIENT};
    Socket(Type type);
    virtual void getData(std::vector<uint8_t>& data) = 0;
    virtual std::unique_ptr<Socket> acceptConnection() = 0;
    virtual int sendData(const std::vector<uint8_t>& data) = 0;
    virtual void closeSocket() = 0;
protected:
    Type type_;
};