#include "AdaptorLayerAppAPI.hh"

void AdaptorLayerAppAPI::registerAppCallbacks(
    AppALDataConfirmCB appALDataConfirmCB
) {
    this->appALDataConfirmCB = appALDataConfirmCB;
}