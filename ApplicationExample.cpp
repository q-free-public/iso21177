#include "ApplicationExample.hh"

#include <iostream>

ApplicationExample::ApplicationExample(SecuritySubsystemAppAPI &secSubsystemAppAPI)
: Application(secSubsystemAppAPI)
{
    std::cerr << "ApplicationExample constructed\n";
}

void ApplicationExample::AppSecureConfigureConfirm(
    SecuritySubsystemAppAPI::AppSecConfigureConfirmResult ret)
{
    std::cerr << " ApplicationExample::AppSecureConfigureConfirm " 
            << (int)(ret) << "\n";
}

void ApplicationExample::AppSecStartSessionIndictation(
    BaseTypes::AppId appId, BaseTypes::SessionId sessionId)
{
    std::cerr << " ApplicationExample::AppSecStartSessionIndictation " 
        << appId << " " << sessionId << "\n";
}
