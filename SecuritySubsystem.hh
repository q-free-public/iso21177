#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"
#include "AdaptorLayerSecSubAPI.hh"
#include "SecureSessionSecSubAPI.hh"

class SecuritySubsystem : public SecuritySubsystemAppAPI {
public:
    SecuritySubsystem();
    void registerAdaptorLayerSecSubAPI(std::weak_ptr<AdaptorLayerSecSubAPI> );
    void registerSecureSessionSecSubAPI(std::weak_ptr<SecureSessionSecSubAPI>);

    virtual void SecSessConfigureConfirm();
    virtual void SecSessStartIndication(
        const BaseTypes::AppId&,
        const BaseTypes::SessionId&,
        const BaseTypes::Certificate&
    );

    virtual void AppSecConfigureRequest(
        const BaseTypes::AppId& appId,
        BaseTypes::Role role,
        const BaseTypes::Socket& socket,
        BaseTypes::SessionType sessionType, // Always External
        bool proxied, // Always False
        const BaseTypes::SessionId& sessionId, // only used if role == CLIENT
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle& cryptomaterialHandle
    );

    virtual void AppSecDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CryptomaterialHandle& cryptoHandle,
        const BaseTypes::Data& data,
        const BaseTypes::SigningParameters& signingParams
    );

    virtual void AppSecIncomingRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apdu,
        bool isIeee1609Dot2Data,
        const BaseTypes::SignedDataVerificationParams& signVerParams
    );
    
private:
    std::weak_ptr<AdaptorLayerSecSubAPI> alAPI;
    std::weak_ptr<SecureSessionSecSubAPI> secSessAPI;
};