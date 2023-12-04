#include "AdaptorLayerAppAPI.hh"

void AdaptorLayerAppAPI::registerAppAPI(std::weak_ptr<AppAdaptorLayerAPI> ptr)
{
    this->appALAPI = ptr;
}