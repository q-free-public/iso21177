#include "SecureSessionSecSubAPI.hh"

#include <iostream>

void SecureSessionSecSubAPI::registerSecSubCallbacks(
    SecSessConfigureConfirmCB secSessConfigureConfirmCB,
    SecSessionStartIndicationCB secSessionStartIndicationCB)
{
    this->secSessConfigureConfirmCB = secSessConfigureConfirmCB;
    this->secSessionStartIndicationCB = secSessionStartIndicationCB;
}
