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
    secSubsystem->registerAdaptorLayerSecSubAPI(adaptorLayer);
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
    std::cerr << "=====> Secure session handshake finished by a client\n";
    secureSession->afterHandshake();

    // Sign data before sending 
    // (it is also possible to send data without signing)
    std::cerr << "=====> App Signing data\n";
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
    std::cerr << "=====> App sending data\n";
    BaseTypes::Data ieee1609Data = {0x05, 0x06};
    appEx->executeWithALAPI([&](AdaptorLayerAppAPI& alAppAPI){
        alAppAPI.AppALDataRequest(
            appId,
            sessionId,
            ieee1609Data);
    });

    std::cerr << "=====> Secure session receive data\n";
    secureSession->receiveData({0x01, 0x03, 0x07});

    
    std::cerr << "=====> App triggering End session\n";
    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secSubAPI){
        secSubAPI.AppSecEndSessionRequest(appId, sessionId);
    });

    std::cerr << "=====> Session Terminated ad session layer\n";
    secureSession->sessionTerminated();

    return 1;
}