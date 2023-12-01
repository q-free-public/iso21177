#include "AdaptorLayerSecSubAPI.hh"

#include <iostream>

void AdaptorLayerSecSubAPI::registerAppCallBacks(
    SecALAccessControlConfirmCB secALAccessControlConfirmCB,
    SecALAccessControlIndictationCB secALAccessControlIndictationCB,
    SecALEndSessionConfirmCB secALEndSessionConfirmCB)
{
    this->secALAccessControlConfirmCB = secALAccessControlConfirmCB;
    this->secALAccessControlIndictationCB = secALAccessControlIndictationCB;
    this->secALEndSessionConfirmCB = secALEndSessionConfirmCB;
    std::cerr << "AdaptorLayerSecSubAPI::registerAppCallBacks\n";
}
