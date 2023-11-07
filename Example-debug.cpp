#include <iostream>

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ApplicationElementExample.hh"
#include "SecuritySubsystemAppAPI.hh"
#include "SecureSession.hh"
#include "SecuritySubsystem.hh"
#include "AdaptorLayer.hh"
#include "SocketTCP.hh"

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
    int port = 1337;
    BaseTypes::Socket serverSocket = std::make_shared<SocketTCP>(Socket::Type::SERVER, port);
    BaseTypes::Socket clientSocket = std::make_shared<SocketTCP>(Socket::Type::CLIENT, port);
    if (serverSocket < 0 || clientSocket < 0) {
        std::cerr << "One of the sockets is invalid\n";
        return -1;
    }

    BaseTypes::SessionId sessionIdServer = 456;
    BaseTypes::SessionId sessionIdClient = 888;
    BaseTypes::CryptomaterialHandle cryptoHandle = "Very Sercure Cert";

    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secAPI) {
        std::cerr << "==> First, a failing example \n";
        secAPI.AppSecConfigureRequest(
            appId,
            BaseTypes::Role::SERVER,
            serverSocket,
            BaseTypes::SessionType::INTERNAL,
            true, 
            sessionIdServer, BaseTypes::TransportMechanismType::UNRELIABLE,
            "Very Secure Certificate");
        std::cerr << "==> Now a working example  - server\n";
        secAPI.AppSecConfigureRequest(
            appId,
            BaseTypes::Role::SERVER,
            serverSocket,
            BaseTypes::SessionType::EXTERNAL,
            false,
            sessionIdServer, BaseTypes::TransportMechanismType::RELIABLE,
            cryptoHandle);
        std::cerr << "==> Now a working example  - client\n";
        secAPI.AppSecConfigureRequest(
            appId,
            BaseTypes::Role::CLIENT,
            clientSocket,
            BaseTypes::SessionType::EXTERNAL,
            false,
            sessionIdClient, BaseTypes::TransportMechanismType::RELIABLE,
            cryptoHandle);
    });
    std::cerr << "=====> Secure session handshake finished by a client\n";
    secureSession->afterHandshake();

    // Sign data before sending 
    // (it is also possible to send data without signing)
    std::cerr << "=====> App Signing data\n";
    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secAPI){
        secAPI.AppSecDataRequest(
            appId,
            sessionIdServer,
            cryptoHandle,
            {0x05, 0x06, 0x07, 0x08},
            "signing params"
        );
    });

    // This is either a secured data, or unsecure data
    // but IEEE1609.2Data in either case
    std::cerr << "=====> Client sending data\n";
    BaseTypes::Data ieee1609Data = {0x05, 0x06};
    appEx->executeWithALAPI([&](AdaptorLayerAppAPI& alAppAPI){
        alAppAPI.AppALDataRequest(
            appId,
            sessionIdClient,
            ieee1609Data);
    });

    std::cerr << "=====> Checking session for data\n";
    secureSession->waitForNetworkInput();

    std::cerr << "=====> Secure session receive data (ProxyPDU)\n";
    secureSession->receiveData({0x00, 0x03, 0x07});

    std::cerr << "=====> Secure session receive data (AccessControlPDU - valid)\n";
    secureSession->receiveData({0x01, 0x03, 0x07});

    std::cerr << "=====> Secure session receive data (AccessControlPDU - not valid)\n";
    secureSession->receiveData({0x01, 0x07, 0x07});

    std::cerr << "=====> Secure session receive data (APDU)\n";
    secureSession->receiveData({0x02, 0x03, 0x07});
    
    std::cerr << "=====> App triggering End session\n";
    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secSubAPI){
        secSubAPI.AppSecEndSessionRequest(appId, sessionIdServer);
    });

    std::cerr << "=====> Session Terminated ad session layer\n";
    secureSession->sessionTerminated();

    std::cerr << "=====> Session Deactivated by App\n";
    appEx->EndSession();

    std::cerr << "=====> Session Deactivated by Security Subsystem\n";
    secSubsystem->endSession();

    return 1;
}