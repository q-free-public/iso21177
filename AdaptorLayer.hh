#pragma once

#include <memory>

#include "AdaptorLayerAppAPI.hh"
#include "SecureSessionALAPI.hh"
#include "AdaptorLayerSecSubAPI.hh"


class AdaptorLayer 
: public AdaptorLayerAppAPI
, public AdaptorLayerSecSubAPI {
public:
    AdaptorLayer() = default;
    
    virtual void AppALDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    );

    virtual void ALSessDataConfirm();
    virtual void ALSessDataIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& alpduReceived
    );
    virtual void ALSessEndSessionConfirm();

    virtual void SecALAccessControlRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    virtual void SecALEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    );

    virtual void registerSecSessAPI(std::weak_ptr<SecureSessionALAPI> ptr);

protected:
    std::weak_ptr<SecureSessionALAPI> secSessALAPI;
};