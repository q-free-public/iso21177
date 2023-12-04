#pragma once

#include <functional>

#include "BaseTypes.hh"

class SecSubAdaptorLayerAPI {
public:
    virtual void SecALAccessControlConfirm() = 0;
    virtual void SecALAccessControlIndictation(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;
    virtual void SecALEndSessionConfirm() = 0;
};

class AdaptorLayerSecSubAPI {
public:
    
    virtual void SecALAccessControlRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;

    virtual void SecALEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    ) = 0;

    virtual void registerSecSubALAPI(std::weak_ptr<SecSubAdaptorLayerAPI> ptr);

protected:
    std::weak_ptr<SecSubAdaptorLayerAPI> secSubALAPI;
};