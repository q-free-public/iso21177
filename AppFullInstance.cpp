#include "AppFullInstance.hh"

#include <unistd.h>
#include "Sockets/SocketTCP.hh"

#include "asn1/Ieee1609Dot2Data.hh"

AppFullInstance::AppFullInstance(
        SecEnt::SecEntCommunicator& secEntComm,
        std::shared_ptr<SecureSession> secSession,
        std::shared_ptr<SecuritySubsystem> secSubsystem,
        std::shared_ptr<AdaptorLayer> adaptorLayer,
        std::shared_ptr<ApplicationElementI> app
    )
: secEntComm_(secEntComm)
, secureSession(secSession)
, secSubsystem(secSubsystem)
, adaptorLayer(adaptorLayer)
, appEx(app)
{
    appEx->registerSecuritySubsystemAPI(secSubsystem);
    secSubsystem->registerAppSecuritySubsystemAPI(appEx);

    appEx->registerAdaptorLayerAPI(adaptorLayer);
    adaptorLayer->registerAppAPI(appEx);

    secSubsystem->registerSecureSessionSecSubAPI(secureSession);
    secureSession->registerSecSubSecureSessionAPI(secSubsystem);

    secSubsystem->registerAdaptorLayerSecSubAPI(adaptorLayer);
    adaptorLayer->registerSecSubALAPI(secSubsystem);

    adaptorLayer->registerSecSessAPI(secureSession);
    secureSession->registerALSecureSessionAPI(adaptorLayer);

    std::cerr <<"Init DONE\n";
}

AppFullInstance::AppFullInstance(
    SecEnt::SecEntCommunicator& secEntComm
)
: AppFullInstance(
    secEntComm,
    std::make_shared<SecureSession>(),
    std::make_shared<SecuritySubsystem>(secEntComm),
    std::make_shared<AdaptorLayer>(),
    std::make_shared<ApplicationElementExample>())
{
}

AppFullInstance::AppFullInstance(
    SecEnt::SecEntCommunicator& secEntComm,
    std::shared_ptr<SecureSession> secSession)
: AppFullInstance(
    secEntComm,
    secSession,
    std::make_shared<SecuritySubsystem>(secEntComm),
    std::make_shared<AdaptorLayer>(),
    std::make_shared<ApplicationElementExample>())
{
}

AppFullInstance::AppFullInstance(
    SecEnt::SecEntCommunicator& secEntComm,
    std::shared_ptr<SecureSession> secSession,
    std::shared_ptr<ApplicationElementI> app)
: AppFullInstance(
    secEntComm,
    secSession,
    std::make_shared<SecuritySubsystem>(secEntComm),
    std::make_shared<AdaptorLayer>(),
    app)
{
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
    BaseTypes::CryptomaterialHandle cryptoHandle = {0xBA, 0x96, 0x84, 0xD4, 0x3A, 0x46, 0x21, 0x77};
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
    std::vector<uint8_t> data_encap = Asn1Helpers::Ieee1609Dot2Data(
        std::integral_constant<
            Asn1Helpers::Ieee1609Dot2Data::type, 
            Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData
        >(), data).getEncodedBuffer();
    call_function_wptr(appEx->aLAppAPI, [&](std::shared_ptr<AdaptorLayerAppAPI> sptr) {
        sptr->AppALDataRequest(
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
    call_function_wptr(appEx->secSubsystemAppAPI, [&](auto sptr) {
        sptr->AppSecEndSessionRequest(
            this->data_->appId,
            this->data_->sessionId
        );
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
