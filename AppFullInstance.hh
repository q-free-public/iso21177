#pragma once

#include <memory>

#include "SecureSession.hh"
#include "SecuritySubsystem.hh"
#include "AdaptorLayer.hh"
#include "ApplicationElementExample.hh"

class AppFullInstance {
public:
    AppFullInstance();
    ~AppFullInstance();

    void configureApplication(
        BaseTypes::SessionId sessionId,
        BaseTypes::Role role);

    void checkIncomingSessions();
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