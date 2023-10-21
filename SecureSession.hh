#pragma once

#include <memory>

#include "SecureSessionSecSubAPI.hh"
#include "SecureSessionALAPI.hh"

class SecureSession : 
        public SecureSessionSecSubAPI,
        public SecureSessionALAPI {
public:
    SecureSession();

    virtual void SecSessConfigureRequest(
        const BaseTypes::AppId& appId,
        BaseTypes::Role role,
        const BaseTypes::Socket socket,
        BaseTypes::SessionType sessionType, // Always External
        bool proxied, // Always False
        const BaseTypes::SessionId& sessionId, // only used if role == CLIENT
        // Only for Type == EXTERNAL start
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle& cryptomaterialHandle,
        const BaseTypes::CertPermissionsPattern& certPermPattern,
        BaseTypes::TimePeriod inactivityTimeout,
        BaseTypes::TimePeriod sessionTimeout,
        // Only for Type == EXTERNAL end
        bool requireClientAuth, // only used for server role
        BaseTypes::TimePeriod incomingRequestTimeout,
        int64_t maxIncomingSessions,
        const BaseTypes::NameConstraints& nameConstraints,
        const BaseTypes::IssuerConstraints& issuerConstraints
    );

    virtual void ALSessDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apduToSend
    );

    virtual void ALSessEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    // This should be triggered by TLS handshake completion
    void afterHandshake();

private:
};