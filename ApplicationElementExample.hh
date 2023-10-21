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

    void AppSecDataConfirm(
        SecuritySubsystemAppAPI::AppSecDataConfirmResult,
        const BaseTypes::SignedData&
    );

    void executeWithSecAPI(std::function<void(SecuritySubsystemAppAPI&)>);

};