#pragma once

#include <functional>

#include "BaseTypes.hh"

class SecureSessionALAPI {
public:
    virtual void ALSessDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& apduToSend
    ) = 0;

    typedef std::function<
        void()
    > ALSessDataConfirmCB;


    typedef std::function<
        void(
            const BaseTypes::AppId& appId,
            const BaseTypes::SessionId& sessionId,
            const BaseTypes::Data& alpduReceived
        )
    > ALSessDataIndicationCB;


    virtual void ALSessEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    ) = 0;

    typedef std::function<void()
    > ALSessEndSessionConfirmCB;


    virtual void registerALCallbacks(
        ALSessDataConfirmCB aLSessDataConfirmCB,
        ALSessDataIndicationCB aLSessDataIndicationCB,
        ALSessEndSessionConfirmCB aLSessEndSessionConfirmCB
    );

protected:
    ALSessDataConfirmCB aLSessDataConfirmCB;
    ALSessDataIndicationCB aLSessDataIndicationCB;
    ALSessEndSessionConfirmCB aLSessEndSessionConfirmCB;
};