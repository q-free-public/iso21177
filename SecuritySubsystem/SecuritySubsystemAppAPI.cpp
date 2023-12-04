#include "SecuritySubsystemAppAPI.hh"

#include <iostream>

void SecuritySubsystemAppAPI::registerAppSecuritySubsystemAPI(std::weak_ptr<AppSecuritySubsystemAPI> ptr)
{
    this->appSecuritySubsystemAPI = ptr;
}

