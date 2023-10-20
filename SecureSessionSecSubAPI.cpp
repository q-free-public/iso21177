#include "SecureSessionSecSubAPI.hh"

#include <iostream>

void SecureSessionSecSubAPI::registerSecSubCallbacks(
        SecSessConfigureConfirmCB secSessConfigureConfirmCB
){
    secSessConfigureConfirmCB = secSessConfigureConfirmCB;
}
