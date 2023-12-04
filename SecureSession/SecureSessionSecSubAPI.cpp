#include "SecureSessionSecSubAPI.hh"

#include <iostream>

void SecureSessionSecSubAPI::registerSecSubSecureSessionAPI(std::weak_ptr<SecSubSecureSessionAPI> ptr)
{
    this->secSubSecureSessionAPI = ptr;
}
