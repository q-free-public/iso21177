#pragma once

#include <vector>

#include "BaseTypes.hh"

// This is quite mysterious, I'm not entirely sure how this should work
class SecuritySubsystemInternalInterface {
public:
    virtual void SecAuthStateRequest(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::DateAndTime& notBefore,
        const BaseTypes::Location& location
    ) = 0;

    virtual void SecAuthStateConfirm(
        const BaseTypes::AppId& appId,
        const BaseTypes::SessionId& sessionId,
        const BaseTypes::CredentialBasedAuthState& credentialBasedAuthState,
        const BaseTypes::DateAndTime& receptionTime
    ) = 0;
};