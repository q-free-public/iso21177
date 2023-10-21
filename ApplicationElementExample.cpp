#include "ApplicationElementExample.hh"

#include <iostream>

ApplicationElementExample::ApplicationElementExample()
: ApplicationElementI()
{
    std::cerr << "ApplicationElementExample constructed\n";
}

void ApplicationElementExample::AppSecureConfigureConfirm(
    SecuritySubsystemAppAPI::AppSecConfigureConfirmResult ret)
{
    std::cerr << " ApplicationElementExample::AppSecureConfigureConfirm " 
            << (int)(ret) << "\n";
}

void ApplicationElementExample::AppSecStartSessionIndictation(
    BaseTypes::AppId appId, BaseTypes::SessionId sessionId)
{
    std::cerr << " ApplicationElementExample::AppSecStartSessionIndictation " 
        << appId << " " << sessionId << "\n";
}

void ApplicationElementExample::AppSecDataConfirm(
    SecuritySubsystemAppAPI::AppSecDataConfirmResult result, 
    const BaseTypes::SignedData &signedData)
{
    std::cerr << "ApplicationElementExample::AppSecDataConfirm " 
    << (int)(result) << " data len: " << signedData.size() << "\n";
}

void ApplicationElementExample::AppALDataConfirm()
{
    std::cerr << "ApplicationElementExample::AppALDataConfirm" << "\n";
}

void ApplicationElementExample::executeWithSecAPI(std::function<void(SecuritySubsystemAppAPI &)> fn)
{
    if (auto sptr = secSubsystemAppAPI.lock()) {
        fn(*sptr);
    } else {
        std::cerr << "!!!!! Sec Sub App API unregistered !!!!\n";
    }
}

void ApplicationElementExample::executeWithALAPI(std::function<void(AdaptorLayerAppAPI &)> fn)
{
    if (auto sptr = aLAppAPI.lock()) {
        fn(*sptr);
    } else {
        std::cerr << "!!!!! AL App API unregistered !!!!\n";
    }
}
