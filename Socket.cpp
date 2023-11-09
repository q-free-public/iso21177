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

bool Socket::attemptHandshakeAsClient()
{
    std::cerr << "Default socket implementation : Socket::attemptHandshakeAsClient\n";
    return true;
}

bool Socket::checkHandshakeAsServer()
{
    std::cerr << "Default socket implementation : Socket::checkHandshakeAsServer\n";
    return true;
}
