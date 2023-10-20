#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

void SecuritySubsystemAppAPI::registerAppCallbacks(
        AppSecConfigureConfirmCB appSecConfigCB,
        AppSecStartSessionIndictationCB appSecStartSessionCB)
{
    appSecConfigureConfirmCB = appSecConfigCB;
    appSecStartSessionIndicatorCB = appSecStartSessionCB;
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
