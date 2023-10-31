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
    this->closeSocket();
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

void AppFullInstance::waitForNetworkInput()
{
    if (!this->data_) {
        std::cerr << "AppFullInstance not initialized\n";
        return;
    }
    secureSession->waitForNetworkInput();
}

void AppFullInstance::sendData(BaseTypes::Data &data)
{
    if (!this->data_) {
        std::cerr << "AppFullInstance not initialized\n";
        return;
    }
    // Sending without signing
    // TODO: it may be necessary to encapsulate data in IEEE1609.2Data
    appEx->executeWithALAPI([&](AdaptorLayerAppAPI& alAppAPI){
        alAppAPI.AppALDataRequest(
            this->data_->appId,
            this->data_->sessionId,
            data);
    });
}

void AppFullInstance::forceEndSession()
{
    if (!this->data_) {
        std::cerr << "AppFullInstance not initialized\n";
        return;
    }
    // Sending without signing
    // TODO: it may be necessary to encapsulate data in IEEE1609.2Data
    appEx->executeWithSecAPI([&](SecuritySubsystemAppAPI& secSubAPI){
        secSubAPI.AppSecEndSessionRequest(
            this->data_->appId,
            this->data_->sessionId);
    });
}

void AppFullInstance::closeSocket()
{
    if (this->data_) {
        if (this->data_->sock >= 0) {
            std::cerr << "Closing socket\n";
            close(this->data_->sock);
            this->data_->sock = -1;
        }
    }
}

AppFullInstance::data_t::data_t(BaseTypes::Role role, BaseTypes::Socket sock, BaseTypes::AppId appId, BaseTypes::SessionId sessionId, BaseTypes::CryptomaterialHandle cryptoHandle)
: role(role)
, sock(sock)
, appId(appId)
, sessionId(sessionId)
, cryptoHandle(cryptoHandle)
{
}
