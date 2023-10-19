#pragma once

#include "Application.hh"

class ApplicationExample : public Application {
public:

    ApplicationExample(SecuritySubsystemAppAPI& secSubsystemAppAPI);
    void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    );

    void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    );

};