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
    // 7.7.5 21177 Any Resuld code that may be returned by
    // IEEE 1609.2
    enum class AppSecDataConfirmResult {
        SUCCESS,
        FAILURE
    };

    virtual ~SecuritySubsystemAppAPI() = default;

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

    typedef std::function<void(AppSecConfigureConfirmResult)>
            AppSecConfigureConfirmCB;


    typedef std::function<
        void(
            const BaseTypes::AppId&,
            const BaseTypes::SessionId&
        )
    > AppSecStartSessionIndictationCB;


    virtual void AppSecDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CryptomaterialHandle& cryptoHandle,
        const BaseTypes::Data& data,
        const BaseTypes::SigningParameters& signingParams
    ) = 0;
    typedef std::function<
        void(
            AppSecDataConfirmResult,
            const BaseTypes::SignedData&
        )
    > AppSecDataConfirmCB;


    virtual void registerAppCallbacks(
        AppSecConfigureConfirmCB,
        AppSecStartSessionIndictationCB,
        AppSecDataConfirmCB
    );

protected:
    AppSecConfigureConfirmCB& getAppSecConfigureConfirmCB();
    AppSecStartSessionIndictationCB& getAppSecStartSessionIndictationCB();

protected:
    AppSecConfigureConfirmCB appSecConfigureConfirmCB;
    AppSecStartSessionIndictationCB appSecStartSessionIndicatorCB;
    AppSecDataConfirmCB appSecDataConfirmCB;
};