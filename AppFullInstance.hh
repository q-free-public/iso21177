#pragma once

#include <memory>

#include "SecureSession/SecureSession.hh"
#include "SecuritySubsystem/SecuritySubsystem.hh"
#include "AdaptorLayer/AdaptorLayer.hh"
#include "ApplicationElementExample.hh"

class AppFullInstance {
public:
    AppFullInstance();
    AppFullInstance(std::shared_ptr<SecureSession> secSession);
    ~AppFullInstance();

    void configureApplication(
        BaseTypes::SessionId sessionId,
        BaseTypes::Role role);

    void waitForNetworkInput();
    void sendData(BaseTypes::Data& data);
    void forceEndSession();
    void closeSocket();
private:
    std::shared_ptr<SecureSession> secureSession;
    std::shared_ptr<SecuritySubsystem> secSubsystem;
    std::shared_ptr<AdaptorLayer> adaptorLayer;
    std::shared_ptr<ApplicationElementExample> appEx;

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