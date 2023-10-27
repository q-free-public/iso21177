#include <iostream>

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ApplicationElementExample.hh"
#include "SecuritySubsystemAppAPI.hh"
#include "SecureSession.hh"
#include "SecuritySubsystem.hh"
#include "AdaptorLayer.hh"

#include "AppFullInstance.hh"

void createApplication(int i, BaseTypes::Role role) {
    int port = 1337;
    BaseTypes::AppId appId = 999;
    BaseTypes::SessionId sessionId = 567 + i;
    BaseTypes::CryptomaterialHandle cryptoHandle = "Very Sercure Cert";

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
    BaseTypes::Socket sock;
    switch (role) {
        case BaseTypes::Role::SERVER: {
            sock = createServerSocket(port);
        }
        case BaseTypes::Role::CLIENT: {
            sock = createClientSocket(port);
        }
    }

    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secAPI) {
        std::cerr << "==> Now a working example  - server\n";
        secAPI.AppSecConfigureRequest(
            appId,
            role,
            sock,
            BaseTypes::SessionType::EXTERNAL,
            false,
            sessionId, BaseTypes::TransportMechanismType::RELIABLE,
            cryptoHandle);
    });
}

int main() {
    AppFullInstance appServ;
    AppFullInstance appClient;

    appServ.configureApplication(123, BaseTypes::Role::SERVER);
    std::cerr << "====> Server now configured\n";
    appClient.configureApplication(456, BaseTypes::Role::CLIENT);
    std::cerr << "====> Client now configured\n";
    std::cerr << "====> Server will check for incoming sessions\n";
    appServ.checkIncomingSessions();
    std::cerr << "====> Client will check for incoming sessions\n";
    appClient.checkIncomingSessions();
}