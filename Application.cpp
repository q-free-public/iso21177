#include "Application.hh"

#include <functional>
#include <iostream>

Application::Application(SecuritySubsystemAppAPI &secSubsystemAppAPI)
: secSubsystemAppAPI(secSubsystemAppAPI) {
    secSubsystemAppAPI.registerAppCallbacks(
        std::bind(&Application::AppSecureConfigureConfirm, this,
                std::placeholders::_1),
        std::bind(&Application::AppSecStartSessionIndictation, this,
                std::placeholders::_1, std::placeholders::_2)
    );

    std::cerr << "Application constructed\n";
}

SecuritySubsystemAppAPI &Application::getSecuritySubsystemAppAPI()
{
    return secSubsystemAppAPI;
}
