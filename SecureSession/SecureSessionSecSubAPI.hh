#pragma once

#include <functional>

#include "BaseTypes.hh"

class SecSubSecureSessionAPI {
public:
    virtual void SecSessConfigureConfirm() = 0;

    virtual void SecSessionStartIndication(
                const BaseTypes::AppId&,
                const BaseTypes::SessionId&,
                const BaseTypes::Certificate&
        ) = 0;

    virtual void SecSessEndSessionIndication(
        const BaseTypes::AppId& appid,
        const BaseTypes::SessionId& sessionId
    ) = 0;

    virtual void SecSessDeactivateConfirm() = 0;

    virtual void getAuthStateReply(
        const BaseTypes::AppId& appid,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CredentialBasedAuthState& authState
        ) = 0;
};

class SecureSessionSecSubAPI {
public:
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
    ) = 0;

    virtual void SecSessDeactivateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secSessInstanceId
    ) = 0;

    virtual void registerSecSubSecureSessionAPI(std::weak_ptr<SecSubSecureSessionAPI> ptr);
    virtual void getAuthState(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId) = 0;

protected:
    std::weak_ptr<SecSubSecureSessionAPI> secSubSecureSessionAPI;
};