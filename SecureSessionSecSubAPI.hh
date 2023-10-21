#pragma once

#include <functional>

#include "BaseTypes.hh"

class SecureSessionSecSubAPI {
public:
    typedef std::function<void()>
            SecSessConfigureConfirmCB;

    typedef std::function<void(
                const BaseTypes::AppId&,
                const BaseTypes::SessionId&,
                const BaseTypes::Certificate&
        )>
            SecSessionStartIndicationCB;

    virtual void registerSecSubCallbacks(
        SecSessConfigureConfirmCB,
        SecSessionStartIndicationCB
    );

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

protected:
    SecSessConfigureConfirmCB secSessConfigureConfirmCB;
    SecSessionStartIndicationCB secSessionStartIndicationCB; 
};