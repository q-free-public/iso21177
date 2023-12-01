#include "SecureSessionALAPI.hh"

void SecureSessionALAPI::registerALCallbacks(
    ALSessDataConfirmCB aLSessDataConfirmCB,
    ALSessDataIndicationCB aLSessDataIndicationCB,
    ALSessEndSessionConfirmCB aLSessEndSessionConfirmCB)
{
    this->aLSessDataConfirmCB = aLSessDataConfirmCB;
    this->aLSessDataIndicationCB = aLSessDataIndicationCB;
    this->aLSessEndSessionConfirmCB = aLSessEndSessionConfirmCB;
}