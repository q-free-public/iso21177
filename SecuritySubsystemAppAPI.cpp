#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

void SecuritySubsystemAppAPI::registerAppCallbacks(
        AppSecConfigureConfirmCB appSecConfigCB,
        AppSecStartSessionIndictationCB appSecStartSessionCB,
        AppSecDataConfirmCB appSecDataConfirmCB,
        AppSecIncomingConfirmCB appSecIncomingConfirmCB)
{
    this->appSecConfigureConfirmCB = appSecConfigCB;
    this->appSecStartSessionIndicatorCB = appSecStartSessionCB;
    this->appSecDataConfirmCB = appSecDataConfirmCB;
    this->appSecIncomingConfirmCB = appSecIncomingConfirmCB;
    std::cerr << "Callbacks registered\n";
}

SecuritySubsystemAppAPI::AppSecConfigureConfirmCB &SecuritySubsystemAppAPI::getAppSecConfigureConfirmCB()
{
    return appSecConfigureConfirmCB;
}

SecuritySubsystemAppAPI::AppSecStartSessionIndictationCB &SecuritySubsystemAppAPI::getAppSecStartSessionIndictationCB()
{
    return appSecStartSessionIndicatorCB;
}
