#pragma once

#include <functional>

#include "BaseTypes.hh"

class AppSecuritySubsystemAPI;

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

    virtual void AppSecDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CryptomaterialHandle& cryptoHandle,
        const BaseTypes::Data& data,
        const BaseTypes::SigningParameters& signingParams
    ) = 0;

    virtual void AppSecIncomingRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apdu,
        bool isIeee1609Dot2Data,
        const BaseTypes::SignedDataVerificationParams& signVerParams
    ) = 0;

    virtual void AppSecEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    ) = 0;

    virtual void AppSecDeactivateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secureSessionId
    ) = 0;

    void registerAppSecuritySubsystemAPI(std::weak_ptr<AppSecuritySubsystemAPI> ptr);

protected:
    std::weak_ptr<AppSecuritySubsystemAPI> appSecuritySubsystemAPI;
};

class AppSecuritySubsystemAPI {
public:

    virtual void AppSecConfigureConfirm(SecuritySubsystemAppAPI::AppSecConfigureConfirmResult) = 0;

    virtual void AppSecStartSessionIndictation(
            const BaseTypes::AppId&,
            const BaseTypes::SessionId&
        ) = 0;

    virtual 
    void AppSecDataConfirm(
        SecuritySubsystemAppAPI::AppSecDataConfirmResult,
        const BaseTypes::SignedData&
    ) = 0;

    virtual void AppSecIncomingConfirm(
            SecuritySubsystemAppAPI::AppSecIncomingConfirmResult
        ) = 0;

    virtual void AppSecDeactivateConfirm() = 0;

    virtual void AppSecDeactivateIndication(const BaseTypes::AppId& appId,
            const BaseTypes::SecureSessionInstanceId& secureSessionId
        ) = 0;

    virtual void AppSecEndSessionIndication(
            const BaseTypes::AppId&,
            const BaseTypes::SessionId&,
            BaseTypes::EnumeratedSecLayer
        ) = 0;
};