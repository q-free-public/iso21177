#pragma once

#include <functional>

#include "BaseTypes.hh"


class SecuritySubsystemAppAPI {
public:
    enum class AppSecConfigureConfirmResult {
        SUCCESS,
        SECURE_SESSION_TYPE_NOT_AVAILABLE,
        SECURE_SESSION_TYPE_NOT_PERMITTED_FOR_THIS_APPLICATION,
        CRYPTOMATERIAL_HANDLE_NOT_PERMITTED
    };
    typedef std::function<void(AppSecConfigureConfirmResult)>
            AppSecConfigureConfirmCB;

    typedef std::function<
        void(
            BaseTypes::AppId,
            BaseTypes::SessionId
        )
    > AppSecStartSessionIndictationCB;

    virtual ~SecuritySubsystemAppAPI() = default;

    virtual void registerAppCallbacks(
        AppSecConfigureConfirmCB,
        AppSecStartSessionIndictationCB
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
    ) = 0;

protected:
    AppSecConfigureConfirmCB& getAppSecConfigureConfirmCB();
    AppSecStartSessionIndictationCB& getAppSecStartSessionIndictationCB();

protected:
    AppSecConfigureConfirmCB appSecConfigureConfirmCB;
    AppSecStartSessionIndictationCB appSecStartSessionIndicatorCB;
};