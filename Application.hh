#pragma once

#include "SecuritySubsystemAppAPI.hh"

class Application {
public:
    Application(SecuritySubsystemAppAPI& secSubsystemAppAPI);

    virtual void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    ) = 0;

    virtual void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    ) = 0;

    SecuritySubsystemAppAPI& getSecuritySubsystemAppAPI();

private:
    SecuritySubsystemAppAPI& secSubsystemAppAPI;
    //AdaptorLayerAppAPI& adaptorLayerAppAPI;
};