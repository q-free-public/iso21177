#pragma once

#include "ApplicationElementI.hh"
#include "BaseTypes.hh"

class ApplicationElementExample : public ApplicationElementI {
public:

    ApplicationElementExample();
    virtual void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    );

    virtual void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    );

    virtual void AppSecDataConfirm(
        SecuritySubsystemAppAPI::AppSecDataConfirmResult,
        const BaseTypes::SignedData&
    );

    virtual void AppALDataConfirm();

    virtual void AppALDataIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    );

    virtual void AppSecIncomingConfirm(
        SecuritySubsystemAppAPI::AppSecIncomingConfirmResult
    );

    virtual void AppSecEndSessionIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& secureSessionId,
        BaseTypes::EnumeratedSecLayer originatingLayer
    );
    virtual void AppSecDeactivateConfirm();
    virtual void AppSecDeactivateIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secureSessionId
    );


    void executeWithSecAPI(std::function<void(SecuritySubsystemAppAPI&)>);
    void executeWithALAPI(std::function<void(AdaptorLayerAppAPI&)>);

    void EndSession();
};