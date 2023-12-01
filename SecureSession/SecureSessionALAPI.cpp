#include "SecureSessionALAPI.hh"

void SecureSessionALAPI::registerALSecureSessionAPI(std::weak_ptr<ALSecureSessionAPI> ptr)
{
    this->alSecureSessionAPI = ptr;
}
