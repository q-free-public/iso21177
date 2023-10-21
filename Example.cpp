#include <iostream>

#include "ApplicationElementExample.hh"
#include "SecuritySubsystemAppAPI.hh"
#include "SecureSession.hh"
#include "SecuritySubsystem.hh"
#include "AdaptorLayer.hh"

int main() {
    std::shared_ptr<SecureSession> secureSession(new SecureSession());
    std::shared_ptr<SecuritySubsystem> secSubsystem(new SecuritySubsystem());
    std::shared_ptr<AdaptorLayer> adaptorLayer(new AdaptorLayer);
    std::shared_ptr<ApplicationElementExample> appEx(new ApplicationElementExample());

    appEx->registerSecuritySubsystemAPI(secSubsystem);
    appEx->registerAdaptorLayerAPI(adaptorLayer);
    secSubsystem->registerSecureSessionSecSubAPI(secureSession);
    adaptorLayer->registerSecSessAPI(secureSession);

    std::cerr <<"Init DONE\n";

    BaseTypes::AppId appId = 123;
    BaseTypes::SessionId sessionId = 456;
    BaseTypes::CryptomaterialHandle cryptoHandle = "Very Sercure Cert";
    
    auto fn = [&](SecuritySubsystemAppAPI& secAPI) {
        std::cerr << "==> First, a failing example \n";
        secAPI.AppSecConfigureRequest(
            123,
            BaseTypes::Role::SERVER,
            12,
            BaseTypes::SessionType::INTERNAL,
            true,
            13, BaseTypes::TransportMechanismType::UNRELIABLE,
            "Very Secure Certificate");
        std::cerr << "==> Now a working example \n";
        secAPI.AppSecConfigureRequest(
            appId,
            BaseTypes::Role::SERVER,
            sessionId,
            BaseTypes::SessionType::EXTERNAL,
            false,
            13, BaseTypes::TransportMechanismType::RELIABLE,
            cryptoHandle);
    };
    appEx->executeWithSecAPI(fn);
    secureSession->afterHandshake();

    // Sign data before sending 
    // (it is also possible to send data without signing)
    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secAPI){
        secAPI.AppSecDataRequest(
            appId,
            sessionId,
            cryptoHandle,
            {0x05, 0x06, 0x07, 0x08},
            "signing params"
        );
    });

    // This is either a secured data, or unsecure data
    // but IEEE1609.2Data in either case
    BaseTypes::Data ieee1609Data = {0x05, 0x06};
    appEx->executeWithALAPI([&](AdaptorLayerAppAPI& alAppAPI){
        alAppAPI.AppALDataRequest(
            appId,
            sessionId,
            ieee1609Data);
    });

    return 1;
}