#pragma once


#include <functional>

#include "BaseTypes.hh"


class AdaptorLayerAppAPI {
public:
    virtual void AppALDataRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;

    typedef std::function<void()>
            AppALDataConfirmCB;
    
    virtual void registerAppCallbacks(
        AppALDataConfirmCB
    );

protected:
    AppALDataConfirmCB appALDataConfirmCB;
};