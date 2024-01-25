#pragma once

#include "ApplicationElementI.hh"
#include "BaseTypes.hh"
#include <future>

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
    void configureApp(
        int port,
        BaseTypes::SessionId sessionId, BaseTypes::Role role,
        BaseTypes::AppId appId, BaseTypes::CryptomaterialHandle cryptoHandle
    );
    void sendDataUnsecured(const BaseTypes::Data& data);
    void sendDataSecured(const BaseTypes::Data& data);
    typedef std::function<void(const std::vector<uint8_t>&, SecuritySubsystemAppAPI::AppSecIncomingConfirmResult)> DataRecvCb_t;
    void registerDataReceivedCallback(DataRecvCb_t dataRecvCb);


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
    DataRecvCb_t dataRecvCallbackFn;
    std::promise<SecuritySubsystemAppAPI::AppSecIncomingConfirmResult> apduVerifyPromise_;
};