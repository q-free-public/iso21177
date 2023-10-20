#include "SecureSessionSecSubAPI.hh"

#include <iostream>

SecureSessionSecSubAPI::SecureSessionSecSubAPI()
{
}

void SecureSessionSecSubAPI::registerSecSubCallbacks(
        SecSessConfigureConfirmCB secSessConfigureConfirmCB
){
    secSessConfigureConfirmCB = secSessConfigureConfirmCB;
}

void SecureSessionSecSubAPI::SecSessConfigureRequest(
        const BaseTypes::AppId &appId, BaseTypes::Role role,
        const BaseTypes::Socket socket,
        BaseTypes::SessionType sessionType, bool proxied,
        const BaseTypes::SessionId &sessionId,
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle &cryptomaterialHandle,
        const BaseTypes::CertPermissionsPattern &certPermPattern,
        BaseTypes::TimePeriod inactivityTimeout,
        BaseTypes::TimePeriod sessionTimeout,
        bool requireClientAuth,
        BaseTypes::TimePeriod incomingRequestTimeout,
        int64_t maxIncomingSessions,
        const BaseTypes::NameConstraints &nameConstraints,
        const BaseTypes::IssuerConstraints &issuerConstraints)
{
    std::cerr << "SecureSessionSecSubAPI::SecSessConfigureRequest" << " APP ID " << appId << "\n";
    if (secSessConfigureConfirmCB) {
        secSessConfigureConfirmCB();
    }
}
