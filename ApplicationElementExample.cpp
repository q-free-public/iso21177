#include "ApplicationElementExample.hh"

#include <iostream>
#include "asn1/APDU.hh"

ApplicationElementExample::ApplicationElementExample()
: ApplicationElementI()
{
    std::cerr << "ApplicationElementExample constructed\n";
}

void ApplicationElementExample::AppSecConfigureConfirm(
    SecuritySubsystemAppAPI::AppSecConfigureConfirmResult ret)
{
    std::cerr << " ApplicationElementExample::AppSecureConfigureConfirm " 
            << (int)(ret) << "\n";
}

void ApplicationElementExample::AppSecStartSessionIndictation(
    const BaseTypes::AppId& appId, const BaseTypes::SessionId& sessionId)
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

void ApplicationElementExample::AppALDataIndication(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &sessionId,
    const BaseTypes::Data &data)
{
    std::cerr << "ApplicationElementExample::AppALDataIndication " << hex_string(data) << "\n";
    Asn1Helpers::APDU apdu(data);
    // TODO: Optional: pre-processing checks (e.2.i p.23)
    if (auto sptr = secSubsystemAppAPI.lock()) {
        sptr->AppSecIncomingRequest(appId, sessionId, apdu.getPayload(), true, {});
    }
}

void ApplicationElementExample::AppSecIncomingConfirm(SecuritySubsystemAppAPI::AppSecIncomingConfirmResult result)
{
    typedef SecuritySubsystemAppAPI::AppSecIncomingConfirmResult Result;
    std::cerr << "ApplicationElementExample::AppSecIncomingConfirm " << (int)(result) << "\n";
    if (result == Result::SUCCESS) {
        std::cerr << "Received APDU is verified and clear for usage\n";
    }
}

void ApplicationElementExample::AppSecEndSessionIndication(
    const BaseTypes::AppId &appId,
    const BaseTypes::SessionId &secureSessionId,
    BaseTypes::EnumeratedSecLayer originatingLayer)
{
    std::cerr << "ApplicationElementExample::AppSecEndSessionIndication\n";
}

void ApplicationElementExample::AppSecDeactivateConfirm()
{
    std::cerr << "ApplicationElementExample::AppSecDeactivateConfirm\n";
}

void ApplicationElementExample::AppSecDeactivateIndication(
    const BaseTypes::AppId &appId,
    const BaseTypes::SecureSessionInstanceId &secureSessionId)
{
    std::cerr << "ApplicationElementExample::AppSecDeactivateIndication\n";
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

void ApplicationElementExample::EndSession()
{
    BaseTypes::AppId appId(11);
    BaseTypes::SecureSessionInstanceId secSessId(99);
    if (auto sptr = secSubsystemAppAPI.lock()) {
        sptr->AppSecDeactivateRequest(appId, secSessId);
    }
}
