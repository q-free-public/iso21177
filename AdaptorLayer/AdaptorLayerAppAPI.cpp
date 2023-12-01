#include "AdaptorLayerAppAPI.hh"

void AdaptorLayerAppAPI::registerAppCallbacks(
    AppALDataConfirmCB appALDataConfirmCB,
    AppALDataIndicationCB appALDataIndicationCB
) {
    this->appALDataConfirmCB = appALDataConfirmCB;
    this->appALDataIndicationCB = appALDataIndicationCB;
}