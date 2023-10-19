#pragma once

#include "ApplicationElementI.hh"
#include "BaseTypes.hh"

class ApplicationElementExample : public ApplicationElementI {
public:

    ApplicationElementExample(SecuritySubsystemAppAPI& secSubsystemAppAPI);
    void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    );

    void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    );

};