#include "ApplicationElementI.hh"

#include <functional>
#include <iostream>

ApplicationElementI::ApplicationElementI()
{
    std::cerr << "ApplicationElementI constructed\n";
}

void ApplicationElementI::registerSecuritySubsystemAPI(std::weak_ptr<SecuritySubsystemAppAPI> ptr)
{
    secSubsystemAppAPI = ptr;
}

void ApplicationElementI::registerAdaptorLayerAPI(std::weak_ptr<AdaptorLayerAppAPI> ptr)
{
    aLAppAPI = ptr;
}
