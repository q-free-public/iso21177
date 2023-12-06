#pragma once

#include "ApplicationElementI.hh"
#include "BaseTypes.hh"

class ApplicationTLS : public ApplicationElementI {
public:

    ApplicationTLS();
    //ISO21177 API
    virtual void AppSecConfigureConfirm(
        SecuritySubsystemAppAPI::AppSecConfigureConfirmResult
    );

    virtual void AppSecStartSessionIndictation(
        const BaseTypes::AppId&,
        const BaseTypes::SessionId&
    );

    virtual void AppSecDataConfirm(
        SecuritySubsystemAppAPI::AppSecDataConfirmResult,
        const BaseTypes::SignedData&
    );

    virtual void AppALDataConfirm();

    virtual void AppALDataIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    );

    virtual void AppSecIncomingConfirm(
        SecuritySubsystemAppAPI::AppSecIncomingConfirmResult
    );

    virtual void AppSecEndSessionIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& secureSessionId,
        BaseTypes::EnumeratedSecLayer originatingLayer
    );
    virtual void AppSecDeactivateConfirm();
    virtual void AppSecDeactivateIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SecureSessionInstanceId& secureSessionId
    );
    // end ISO21177 API

    // void registerEndCallback(std::function<void()> fn);
    void configureApp(BaseTypes::SessionId sessionId, BaseTypes::Role role);
    void sendDataUnsecured(const BaseTypes::Data& data);
    void sendDataSecured(const BaseTypes::Data& data);
    


    void executeWithSecAPI(std::function<void(SecuritySubsystemAppAPI&)>);
    void executeWithALAPI(std::function<void(AdaptorLayerAppAPI&)>);

    void EndSession();
private:
    struct data_t {
        BaseTypes::Role role;
        BaseTypes::Socket sock;
        BaseTypes::AppId appId;
        BaseTypes::SessionId sessionId;
        BaseTypes::CryptomaterialHandle cryptoHandle;

        data_t(
            BaseTypes::Role role,
            BaseTypes::Socket sock,
            BaseTypes::AppId appId,
            BaseTypes::SessionId sessionId,
            BaseTypes::CryptomaterialHandle cryptoHandle);
    };
    std::shared_ptr<data_t> data_;
};