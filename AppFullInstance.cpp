#include "AppFullInstance.hh"

#include <unistd.h>
#include "Sockets/SocketTCP.hh"

#include "asn1/Ieee1609Dot2Data.hh"

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

AppFullInstance::AppFullInstance(std::shared_ptr<SecureSession> secSession)
: secureSession(secSession)
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
}

void AppFullInstance::configureApplication(
    BaseTypes::SessionId sessionId, BaseTypes::Role role)
{
    if (this->data_) {
        std::cerr << "Application already configured\n";
        return;
    }
    int port = 2337;
    BaseTypes::AppId appId = 623;
    BaseTypes::CryptomaterialHandle cryptoHandle = {0x1D, 0x1B, 0x90, 0x41, 0x03, 0xAF, 0x03, 0xD2};
    BaseTypes::Socket sock;
    switch (role) {
        case BaseTypes::Role::SERVER: {
            sock = std::make_shared<SocketTCP>(Socket::Type::SERVER, port);
            break;
        }
        case BaseTypes::Role::CLIENT: {
            sock = std::make_shared<SocketTCP>(Socket::Type::CLIENT, port);
            break;
        }
    }
    this->data_ = std::make_shared<data_t>(role, sock, appId, sessionId, cryptoHandle);
    
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
    // TODO: it may be necessary to sign data
    std::vector<uint8_t> data_encap = Asn1Helpers::Ieee1609Dot2Data(std::integral_constant<Asn1Helpers::Ieee1609Dot2Data::type, Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData>(), data).getEncodedBuffer();
    appEx->executeWithALAPI([&](AdaptorLayerAppAPI& alAppAPI){
        alAppAPI.AppALDataRequest(
            this->data_->appId,
            this->data_->sessionId,
            data_encap);
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
        std::cerr << "Try to close socket\n";
        this->data_->sock->closeSocket();
    } else {
        std::cerr << "No data - failed to close the socket\n";
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
