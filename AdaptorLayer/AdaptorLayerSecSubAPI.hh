#pragma once

#include <functional>

#include "BaseTypes.hh"

class AdaptorLayerSecSubAPI {
public:
    
    virtual void SecALAccessControlRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::Data& data
    ) = 0;
    typedef std::function<
        void()
    > SecALAccessControlConfirmCB;
    typedef std::function<
        void(
            const BaseTypes::AppId& appId,
            const BaseTypes::SessionId& sessionId,
            const BaseTypes::Data& data
        )
    > SecALAccessControlIndictationCB;

    virtual void SecALEndSessionRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId
    ) = 0;
    typedef std::function<
        void()
    > SecALEndSessionConfirmCB;

    virtual void registerAppCallBacks(
        SecALAccessControlConfirmCB secALAccessControlConfirmCB,
        SecALAccessControlIndictationCB secALAccessControlIndictationCB,
        SecALEndSessionConfirmCB secALEndSessionConfirmCB
    );

protected:
    SecALAccessControlConfirmCB secALAccessControlConfirmCB;
    SecALAccessControlIndictationCB secALAccessControlIndictationCB;
    SecALEndSessionConfirmCB secALEndSessionConfirmCB;
};