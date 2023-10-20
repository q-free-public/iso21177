#include "SecuritySubsystem.hh"

#include <memory>
#include <iostream>
#include <functional>

#include "SecuritySubsystemAppAPI.hh"

SecuritySubsystem::SecuritySubsystem()
{
}

void SecuritySubsystem::registerAdaptorLayerSecSubAPI(
        std::weak_ptr<AdaptorLayerSecSubAPI> aLSecSubAPI)
{
    alAPI = aLSecSubAPI;
}

void SecuritySubsystem::registerSecureSessionSecSubAPI(
        std::weak_ptr<SecureSessionSecSubAPI> secSessAPI)
{
    secSessAPI = secSessAPI;
    if (auto sptr = secSessAPI.lock()) {
        sptr->registerSecSubCallbacks(
            std::bind(&SecuritySubsystem::SecSessConfigureConfirm, this)
        );
    }
}

std::weak_ptr<SecuritySubsystemAppAPI> SecuritySubsystem::getAppAPI()
{
    return shared_from_this();
}

void SecuritySubsystem::SecSessConfigureConfirm()
{
    std::cerr << "SecuritySubsystem::SecSessConfigureConfirm" << "\n";
}

void SecuritySubsystem::AppSecConfigureRequest(
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

    std::cerr << "SecureSessionSecSubAPI::SecSessConfigureRequest" << " APP ID " << appId << "\n";
    if (this->appSecConfigureConfirmCB) {
        this->appSecConfigureConfirmCB(result);
    }
    if (sessionType == BaseTypes::SessionType::EXTERNAL) {
        // Cryptographic session is required
        if (auto sptr = secSessAPI.lock()) {
            BaseTypes::CertPermissionsPattern certPermPattern;
            BaseTypes::TimePeriod inactivityTimeout = 100;
            BaseTypes::TimePeriod sessionTimeout = 100;
            bool requireClientAuth = true;
            BaseTypes::TimePeriod incomingRequestTimeout = 100;
            int64_t maxIncomingSessions = 1;
            BaseTypes::NameConstraints nameConstraints;
            BaseTypes::IssuerConstraints issuerConstraints;
            sptr->SecSessConfigureRequest(
                appId, role, socket, sessionType, 
                proxied, sessionId, transportMechanismType,
                cryptomaterialHandle, 
                certPermPattern, inactivityTimeout, sessionTimeout,
                requireClientAuth, incomingRequestTimeout,
                maxIncomingSessions, nameConstraints,
                issuerConstraints
            );
        }
    }
}
