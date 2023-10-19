#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

SecuritySubsystemAppAPI::SecuritySubsystemAppAPI()
{
}

void SecuritySubsystemAppAPI::registerAppCallbacks(
        AppSecConfigureConfirmCB appSecConfigCB,
        AppSecStartSessionIndictationCB appSecStartSessionCB)
{
    appSecConfigureConfirmCB = appSecConfigCB;
    appSecStartSessionIndicatorCB = appSecStartSessionCB;
    std::cerr << "Callbacks registered\n";
}

void SecuritySubsystemAppAPI::AppSecConfigureRequest(
        const BaseTypes::AppId &appId, BaseTypes::Role role,
        const BaseTypes::Socket &socket,
        BaseTypes::SessionType sessionType,
        bool proxied, const BaseTypes::SessionId &sessionId,
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle &cryptomaterialHandle)
{
    std::cerr << "SecuritySubsystemAppAPI::AppSecConfigureRequest " << "AID " << appId << "\n";
    AppSecConfigureConfirmResult result = AppSecConfigureConfirmResult::SUCCESS;
    if (proxied) {
        std::cerr << "unsupported proxied value : True\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }
    if (transportMechanismType == BaseTypes::TransportMechanismType::UNRELIABLE) {
        std::cerr << "unsupported transportMechanismType : unreliable\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }
    if (sessionType == BaseTypes::SessionType::INTERNAL) {
        std::cerr << "unsupported SessionType : internal\n";
        result = AppSecConfigureConfirmResult::SECURE_SESSION_TYPE_NOT_AVAILABLE;
    }
    if (appSecConfigureConfirmCB) {
        appSecConfigureConfirmCB(result);
    }
}
