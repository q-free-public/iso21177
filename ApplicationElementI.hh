#pragma once

#include <memory>

#include "AdaptorLayer/AdaptorLayerAppAPI.hh"
#include "SecuritySubsystem/SecuritySubsystemAppAPI.hh"

class ApplicationElementI {
public:
    ApplicationElementI();

    virtual void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    ) = 0;

    virtual void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    ) = 0;

    virtual void AppSecDataConfirm(
        SecuritySubsystemAppAPI::AppSecDataConfirmResult,
        const BaseTypes::SignedData&
    ) = 0;

    virtual void AppALDataIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;

    virtual void AppALDataConfirm() = 0;

    virtual void AppSecIncomingConfirm(
        SecuritySubsystemAppAPI::AppSecIncomingConfirmResult
    ) = 0;

    virtual void AppSecEndSessionIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& secureSessionId,
        BaseTypes::EnumeratedSecLayer originatingLayer
    ) = 0;
    virtual void AppSecDeactivateConfirm() = 0;
    virtual void AppSecDeactivateIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secureSessionId
    ) = 0;

    virtual void registerSecuritySubsystemAPI(std::weak_ptr<SecuritySubsystemAppAPI> ptr);
    virtual void registerAdaptorLayerAPI(std::weak_ptr<AdaptorLayerAppAPI> ptr);

protected:
    std::weak_ptr<SecuritySubsystemAppAPI> secSubsystemAppAPI;
    std::weak_ptr<AdaptorLayerAppAPI> aLAppAPI;
};