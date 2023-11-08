#include "Socket.hh"

Socket::Socket(Type type)
: type_(type)
{
}

Socket::Socket(const Socket &s)
: type_(s.type_)
{
}
