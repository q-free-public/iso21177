#include "AdaptorLayerSecSubAPI.hh"

#include <iostream>

void AdaptorLayerSecSubAPI::registerSecSubALAPI(std::weak_ptr<SecSubAdaptorLayerAPI> ptr)
{
    this->secSubALAPI = ptr;
}
