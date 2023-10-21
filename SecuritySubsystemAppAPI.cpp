#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

void SecuritySubsystemAppAPI::registerAppCallbacks(
        AppSecConfigureConfirmCB appSecConfigCB,
        AppSecStartSessionIndictationCB appSecStartSessionCB,
        AppSecDataConfirmCB appSecDataConfirmCB)
{
    this->appSecConfigureConfirmCB = appSecConfigCB;
    this->appSecStartSessionIndicatorCB = appSecStartSessionCB;
    this->appSecDataConfirmCB = appSecDataConfirmCB;
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
