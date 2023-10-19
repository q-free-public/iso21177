#include "ApplicationElementI.hh"

#include <functional>
#include <iostream>

ApplicationElementI::ApplicationElementI(SecuritySubsystemAppAPI &secSubsystemAppAPI)
: secSubsystemAppAPI(secSubsystemAppAPI) {
    secSubsystemAppAPI.registerAppCallbacks(
        std::bind(&ApplicationElementI::AppSecureConfigureConfirm, this,
                std::placeholders::_1),
        std::bind(&ApplicationElementI::AppSecStartSessionIndictation, this,
                std::placeholders::_1, std::placeholders::_2)
    );

    std::cerr << "ApplicationElementI constructed\n";
}

SecuritySubsystemAppAPI &ApplicationElementI::getSecuritySubsystemAppAPI()
{
    return secSubsystemAppAPI;
}
