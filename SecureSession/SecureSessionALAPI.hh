#pragma once

#include <functional>

#include "BaseTypes.hh"

class ALSecureSessionAPI {
public:
    virtual void ALSessDataConfirm() = 0;
    virtual void ALSessDataIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& alpduReceived
    ) = 0;
    virtual void ALSessEndSessionConfirm() = 0;
};

class SecureSessionALAPI {
public:
    virtual void ALSessDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apduToSend
    ) = 0;

    virtual void ALSessEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    ) = 0;

    virtual void registerALSecureSessionAPI(std::weak_ptr<ALSecureSessionAPI> ptr);

protected:
    std::weak_ptr<ALSecureSessionAPI> alSecureSessionAPI;
};