#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"
#include "AdaptorLayerSecSubAPI.hh"
#include "SecureSessionSecSubAPI.hh"

class SecuritySubsystem : public std::enable_shared_from_this<SecuritySubsystem>,
        public SecuritySubsystemAppAPI {
public:
    SecuritySubsystem();
    void registerAdaptorLayerSecSubAPI(std::weak_ptr<AdaptorLayerSecSubAPI> );
    void registerSecureSessionSecSubAPI(std::weak_ptr<SecureSessionSecSubAPI>);
    std::weak_ptr<SecuritySubsystemAppAPI> getAppAPI();

    virtual void SecSessConfigureConfirm();

    virtual void AppSecConfigureRequest(
        const BaseTypes::AppId& appId,
        BaseTypes::Role role,
        const BaseTypes::Socket& socket,
        BaseTypes::SessionType sessionType, // Always External
        bool proxied, // Always False
        const BaseTypes::SessionId& sessionId, // only used if role == CLIENT
        BaseTypes::TransportMechanismType transportMechanismType,
        const BaseTypes::CryptomaterialHandle& cryptomaterialHandle
    );
    
private:
    std::weak_ptr<AdaptorLayerSecSubAPI> alAPI;
    std::weak_ptr<SecureSessionSecSubAPI> secSessAPI;
};