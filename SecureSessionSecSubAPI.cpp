#include "SecureSessionSecSubAPI.hh"

#include <iostream>

void SecureSessionSecSubAPI::registerSecSubCallbacks(
    SecSessConfigureConfirmCB secSessConfigureConfirmCB, 
    SecSessionStartIndicationCB secSessionStartIndicationCB, 
    SecSessEndSessionIndicationCB secSessEndSessionIndicationCB,
    SecSessDeactivateConfirmCB secSessDeactivateConfirmCB)
{
    this->secSessConfigureConfirmCB = secSessConfigureConfirmCB;
    this->secSessionStartIndicationCB = secSessionStartIndicationCB;
    this->secSessEndSessionIndicationCB = secSessEndSessionIndicationCB;
    this->secSessDeactivateConfirmCB = secSessDeactivateConfirmCB;
}
