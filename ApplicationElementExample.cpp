#include "ApplicationElementExample.hh"

#include <iostream>

ApplicationElementExample::ApplicationElementExample(SecuritySubsystemAppAPI &secSubsystemAppAPI)
: ApplicationElementI(secSubsystemAppAPI)
{
    std::cerr << "ApplicationElementExample constructed\n";
}

void ApplicationElementExample::AppSecureConfigureConfirm(
    SecuritySubsystemAppAPI::AppSecConfigureConfirmResult ret)
{
    std::cerr << " ApplicationElementExample::AppSecureConfigureConfirm " 
            << (int)(ret) << "\n";
}

void ApplicationElementExample::AppSecStartSessionIndictation(
    BaseTypes::AppId appId, BaseTypes::SessionId sessionId)
{
    std::cerr << " ApplicationElementExample::AppSecStartSessionIndictation " 
        << appId << " " << sessionId << "\n";
}
