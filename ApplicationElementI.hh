#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"

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

    virtual void registerSecuritySubsystemAPI(std::weak_ptr<SecuritySubsystemAppAPI> ptr);

protected:
    std::weak_ptr<SecuritySubsystemAppAPI> secSubsystemAppAPI;
    //AdaptorLayerAppAPI& adaptorLayerAppAPI;
};