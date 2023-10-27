#include "AppFullInstance.hh"

#include <unistd.h>

AppFullInstance::AppFullInstance()
: secureSession(new SecureSession())
, secSubsystem(new SecuritySubsystem())
, adaptorLayer(new AdaptorLayer())
, appEx(new ApplicationElementExample())
{
    appEx->registerSecuritySubsystemAPI(secSubsystem);
    appEx->registerAdaptorLayerAPI(adaptorLayer);
    secSubsystem->registerSecureSessionSecSubAPI(secureSession);
    secSubsystem->registerAdaptorLayerSecSubAPI(adaptorLayer);
    adaptorLayer->registerSecSessAPI(secureSession);

    std::cerr <<"Init DONE\n";
}

AppFullInstance::~AppFullInstance()
{
    if (this->data_) {
        std::cerr << "Closing socket\n";
        close(this->data_->sock);
    }
}

void AppFullInstance::configureApplication(
    BaseTypes::SessionId sessionId, BaseTypes::Role role)
{
    if (this->data_) {
        std::cerr << "Application already configured\n";
        return;
    }
    int port = 2337;
    BaseTypes::AppId appId = 999;
    BaseTypes::CryptomaterialHandle cryptoHandle = "Very Sercure Cert";
    BaseTypes::Socket sock;
    switch (role) {
        case BaseTypes::Role::SERVER: {
            sock = createServerSocket(port);
            break;
        }
        case BaseTypes::Role::CLIENT: {
            sock = createClientSocket(port);
            break;
        }
    }
    std::cerr << "Socket number " << sock << "\n";
    this->data_ = std::make_shared<data_t>(role, sock, appId, sessionId, cryptoHandle);
    std::cerr << "Socket number " << this->data_->sock << "\n";

    secSubsystem->AppSecConfigureRequest(
            this->data_->appId,
            this->data_->role,
            this->data_->sock,
            BaseTypes::SessionType::EXTERNAL,
            false,
            this->data_->sessionId, BaseTypes::TransportMechanismType::RELIABLE,
            this->data_->cryptoHandle);
}

void AppFullInstance::checkIncomingSessions()
{
    if (!this->data_) {
        std::cerr << "AppFullInstance not initialized\n";
        return;
    }
    if (this->data_->role != BaseTypes::Role::SERVER) {
        std::cerr << "Unable to checkIncomingSessions when not in SERVER mode\n";
    }
    secureSession->checkForSessions();
}

AppFullInstance::data_t::data_t(BaseTypes::Role role, BaseTypes::Socket sock, BaseTypes::AppId appId, BaseTypes::SessionId sessionId, BaseTypes::CryptomaterialHandle cryptoHandle)
: role(role)
, sock(sock)
, appId(appId)
, sessionId(sessionId)
, cryptoHandle(cryptoHandle)
{
}
