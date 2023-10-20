#pragma once

#include <memory>

#include "SecuritySubsystemAppAPI.hh"
#include "AdaptorLayerSecSubAPI.hh"

class SecuritySubsystem {
public:
    SecuritySubsystem();
    void registerAdaptorLayerSecSubAPI(std::weak_ptr<AdaptorLayerSecSubAPI> );
    std::weak_ptr<SecuritySubsystemAppAPI> getAppAPI();
    
private:
    std::shared_ptr<SecuritySubsystemAppAPI> appAPI;
    
    std::weak_ptr<AdaptorLayerSecSubAPI> alAPI;
};