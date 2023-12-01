#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"
#include "AdaptorLayer/AdaptorLayerSecSubAPI.hh"
#include "SecureSession/SecureSessionSecSubAPI.hh"
#include "SecuritySubsystemInternalInterface.hh"

class SecuritySubsystem 
: public SecuritySubsystemAppAPI
, public SecuritySubsystemInternalInterface {
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

    virtual void AppSecEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    virtual void AppSecDeactivateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secureSessionId
    );

    virtual void SecALAccessControlConfirm();
    virtual void SecALAccessControlIndictation(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    );
    virtual void SecALEndSessionConfirm();

    virtual void SecSessEndSessionIndication(
        const BaseTypes::AppId& appid,
        const BaseTypes::SessionId& sessionId
    );

    virtual void SecSessDeactivateConfirm();

    virtual void SecAuthStateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::DateAndTime& notBefore,
        const BaseTypes::Location& location
    );

    virtual void SecAuthStateConfirm(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CredentialBasedAuthState& credentialBasedAuthState,
        const BaseTypes::DateAndTime& receptionTime
    );

    virtual void sendAccessControlPdu();

    virtual void forceEndSession(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    virtual void endSession();
    
private:
    std::weak_ptr<AdaptorLayerSecSubAPI> alAPI;
    std::weak_ptr<SecureSessionSecSubAPI> secSessAPI;
};