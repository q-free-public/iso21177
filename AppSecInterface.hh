#pragma once

#include "BaseTypes.hh"



class AppSecInterface {
public:

    void AppSecStartSessionIndication(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,

    )
};