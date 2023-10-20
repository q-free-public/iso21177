#pragma once

#include "ApplicationElementI.hh"
#include "BaseTypes.hh"

class ApplicationElementExample : public ApplicationElementI {
public:

    ApplicationElementExample();
    void AppSecureConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    );

    void AppSecStartSessionIndictation(
        BaseTypes::AppId,
        BaseTypes::SessionId
    );

    void executeWithSecAPI(std::function<void(SecuritySubsystemAppAPI&)>);

};