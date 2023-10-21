#pragma once

#include <memory>

#include "AdaptorLayerAppAPI.hh"
#include "SecureSessionALAPI.hh"


class AdaptorLayer : public AdaptorLayerAppAPI {
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

    virtual void registerSecSessAPI(std::weak_ptr<SecureSessionALAPI> ptr);

protected:
    std::weak_ptr<SecureSessionALAPI> secSessALAPI;
};