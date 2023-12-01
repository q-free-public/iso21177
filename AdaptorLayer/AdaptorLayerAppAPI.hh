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
    

    typedef std::function<
        void(
            const BaseTypes::AppId&,
            const BaseTypes::SessionId&,
            const BaseTypes::Data&
        )
    > AppALDataIndicationCB;

    virtual void registerAppCallbacks(
        AppALDataConfirmCB,
        AppALDataIndicationCB
    );

protected:
    AppALDataConfirmCB appALDataConfirmCB;
    AppALDataIndicationCB appALDataIndicationCB;
};