#include "SecureSession.hh"

SecureSession::SecureSession()
: secSubAPI()
{
}

SecureSessionSecSubAPI &SecureSession::getSecSubAPI()
{
    return secSubAPI;
}
