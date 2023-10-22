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
    enum class AppSecIncomingConfirmResult {
        SUCCESS,
        INVALID_IEEE1609DOT2DATA_TYPE,
        INVALID_SIGNED_IEEE1609DOT2_DATA,
        INVALID_APDU_AS_PER_ACCESS_CONTROL_POLICY_REQUEST_SENT,
        INVALID_APDU_AS_PER_ACCESS_CONTROL_POLICY_NO_REQUEST_SENT
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


    virtual void AppSecIncomingRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apdu,
        bool isIeee1609Dot2Data,
        const BaseTypes::SignedDataVerificationParams& signVerParams
    ) = 0;
    typedef std::function<
        void(
            AppSecIncomingConfirmResult
        )
    > AppSecIncomingConfirmCB;

    virtual void registerAppCallbacks(
        AppSecConfigureConfirmCB,
        AppSecStartSessionIndictationCB,
        AppSecDataConfirmCB,
        AppSecIncomingConfirmCB
    );

protected:
    AppSecConfigureConfirmCB& getAppSecConfigureConfirmCB();
    AppSecStartSessionIndictationCB& getAppSecStartSessionIndictationCB();

protected:
    AppSecConfigureConfirmCB appSecConfigureConfirmCB;
    AppSecStartSessionIndictationCB appSecStartSessionIndicatorCB;
    AppSecDataConfirmCB appSecDataConfirmCB;
    AppSecIncomingConfirmCB appSecIncomingConfirmCB;
};