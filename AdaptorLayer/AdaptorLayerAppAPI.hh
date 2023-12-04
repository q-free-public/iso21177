#pragma once


#include <functional>

#include "BaseTypes.hh"

class AppAdaptorLayerAPI {
public:
    virtual void AppALDataConfirm() = 0;
    virtual void AppALDataIndication(
            const BaseTypes::AppId&,
            const BaseTypes::SessionId&,
            const BaseTypes::Data&
        ) = 0;
};

class AdaptorLayerAppAPI {
public:
    virtual void AppALDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;

    virtual void registerAppAPI(std::weak_ptr<AppAdaptorLayerAPI> ptr);
protected:
    std::weak_ptr<AppAdaptorLayerAPI> appALAPI;
};