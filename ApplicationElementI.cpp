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
    if (std::shared_ptr<SecuritySubsystemAppAPI> spt = secSubsystemAppAPI.lock()) {
        spt->registerAppCallbacks(
            std::bind(&ApplicationElementI::AppSecureConfigureConfirm, this,
                    std::placeholders::_1),
            std::bind(&ApplicationElementI::AppSecStartSessionIndictation, this,
                    std::placeholders::_1, std::placeholders::_2)
        );
    }
}
