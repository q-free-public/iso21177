#include "Socket.hh"
#include <iostream>

Socket::Socket(Type type)
: type_(type)
{
}

Socket::Socket(const Socket &s)
: type_(s.type_)
{
}

bool Socket::attemptHandshake(const BaseTypes::AppId &appId, const BaseTypes::CryptomaterialHandle &clientHandle)
{
    std::cerr << "Default socket implementation : Socket::attemptHandshake\n";
    return true;
}

bool Socket::checkHandshakeAsServer()
{
    std::cerr << "Default socket implementation : Socket::checkHandshakeAsServer\n";
    return true;
}
