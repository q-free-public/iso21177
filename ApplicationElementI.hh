#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"
#include "AdaptorLayerAppAPI.hh"

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

    virtual void AppALDataConfirm() = 0;

    virtual void registerSecuritySubsystemAPI(std::weak_ptr<SecuritySubsystemAppAPI> ptr);
    virtual void registerAdaptorLayerAPI(std::weak_ptr<AdaptorLayerAppAPI> ptr);

protected:
    std::weak_ptr<SecuritySubsystemAppAPI> secSubsystemAppAPI;
    std::weak_ptr<AdaptorLayerAppAPI> aLAppAPI;
};