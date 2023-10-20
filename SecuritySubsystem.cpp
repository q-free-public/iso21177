#include "SecuritySubsystem.hh"

#include <memory>

#include "SecuritySubsystemAppAPI.hh"

SecuritySubsystem::SecuritySubsystem()
: appAPI(std::make_shared<SecuritySubsystemAppAPI>(SecuritySubsystemAppAPI()))
{
}

void SecuritySubsystem::registerAdaptorLayerSecSubAPI(std::weak_ptr<AdaptorLayerSecSubAPI> aLSecSubAPI)
{
    alAPI = aLSecSubAPI;
}

std::weak_ptr<SecuritySubsystemAppAPI> SecuritySubsystem::getAppAPI()
{
    return std::weak_ptr<SecuritySubsystemAppAPI>(appAPI);
}
