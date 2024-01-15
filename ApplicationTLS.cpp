#include "ApplicationTLS.hh"

#include "Sockets/SocketTCP.hh"
#include "asn1/Ieee1609Dot2Data.hh"
#include "asn1/APDU.hh"

ApplicationTLS::ApplicationTLS()
: data_(nullptr)
{
}

void ApplicationTLS::AppSecConfigureConfirm(SecuritySubsystemAppAPI::AppSecConfigureConfirmResult res)
{
    std::cerr << "!!ApplicationTLS::AppSecConfigureConfirm " << static_cast<uint8_t>(res) << "\n";
}

void ApplicationTLS::AppSecStartSessionIndictation(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId)
{
    std::cerr << "!!ApplicationTLS::AppSecStartSessionIndictation " << appId << " " << sessionId << "\n";
}

void ApplicationTLS::AppSecDataConfirm(SecuritySubsystemAppAPI::AppSecDataConfirmResult res,
        const BaseTypes::SignedData &signedData)
{
    std::cerr << "!!ApplicationTLS::AppSecDataConfirm " 
        << (res == SecuritySubsystemAppAPI::AppSecDataConfirmResult::SUCCESS) 
        << "\n";
    signedData.debugPrint();
    // this was signed - now we want to send
    if (res == SecuritySubsystemAppAPI::AppSecDataConfirmResult::SUCCESS) {
        call_function_wptr(this->aLAppAPI, [&](std::shared_ptr<AdaptorLayerAppAPI> sptr) {
            sptr->AppALDataRequest(
                this->data_->appId,
                this->data_->sessionId,
                signedData.getEncodedBuffer());
        });
    } else {
        std::cerr << "!!ApplicationTLS::AppSecDataConfirm : failed to sign data, will not be sent out \n";
        throw std::runtime_error("ApplicationTLS::AppSecDataConfirm : failed to sign data, will not be sent out");
    }
}

void ApplicationTLS::AppALDataConfirm()
{
    std::cerr << "!!ApplicationTLS::AppALDataConfirm " << "\n";
}

void ApplicationTLS::AppALDataIndication(const BaseTypes::AppId &appId, 
        const BaseTypes::SessionId &sessionId, const BaseTypes::Data &data)
{
    
    std::cerr << "!!ApplicationTLS::AppALDataIndication: local session info " << appId << " " << sessionId << "\n";
    std::cerr << "Application data received\n";
    Asn1Helpers::APDU apdu_parsed(data);
    Asn1Helpers::Ieee1609Dot2Data data_parsed(apdu_parsed.getPayload());
    data_parsed.debugPrint();
    std::vector<uint8_t> data_payload = data_parsed.getPayload();
    std::cerr << "payload " << hex_string(data_payload) << "\n";
}

void ApplicationTLS::AppSecIncomingConfirm(SecuritySubsystemAppAPI::AppSecIncomingConfirmResult)
{
}

void ApplicationTLS::AppSecEndSessionIndication(const BaseTypes::AppId &appId, const BaseTypes::SessionId &secureSessionId, BaseTypes::EnumeratedSecLayer originatingLayer)
{
    std::cerr << "############Session was ended!!!\n";
}

void ApplicationTLS::AppSecDeactivateConfirm()
{
}

void ApplicationTLS::AppSecDeactivateIndication(const BaseTypes::AppId &appId, const BaseTypes::SecureSessionInstanceId &secureSessionId)
{
    std::cerr << "##########Session was deactivated!!!\n";}

void ApplicationTLS::configureApp(BaseTypes::SessionId sessionId, BaseTypes::Role role)
{
    int port = 2337;
    BaseTypes::AppId appId = 623;
    BaseTypes::CryptomaterialHandle cryptoHandle = {0xBA, 0x96, 0x84, 0xD4, 0x3A, 0x46, 0x21, 0x77};
    configureApp(port, sessionId, role, appId, cryptoHandle);
}

void ApplicationTLS::configureApp(
    int port,
    BaseTypes::SessionId sessionId, BaseTypes::Role role,
    BaseTypes::AppId appId, BaseTypes::CryptomaterialHandle cryptoHandle
)
{
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
    call_function_wptr(this->secSubsystemAppAPI, [&](std::shared_ptr<SecuritySubsystemAppAPI> secSub) {
        secSub->AppSecConfigureRequest(
            this->data_->appId,
            this->data_->role,
            this->data_->sock,
            BaseTypes::SessionType::EXTERNAL,
            false,
            this->data_->sessionId, BaseTypes::TransportMechanismType::RELIABLE,
            this->data_->cryptoHandle);
    });
}

void ApplicationTLS::sendDataUnsecured(const BaseTypes::Data& data)
{
    std::vector<uint8_t> data_encap = Asn1Helpers::Ieee1609Dot2Data(
        std::integral_constant<
            Asn1Helpers::Ieee1609Dot2Data::type,
            Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData
        >(), data).getEncodedBuffer();
    call_function_wptr(this->aLAppAPI, [&](std::shared_ptr<AdaptorLayerAppAPI> sptr) {
        sptr->AppALDataRequest(
            this->data_->appId,
            this->data_->sessionId,
            data_encap);
    });
}

void ApplicationTLS::sendDataSecured(const BaseTypes::Data &data)
{
    if (!data_) {
        throw std::runtime_error("Application uninitialized");
    }
    BaseTypes::SigningParameters signParams = "no-params";
    call_function_wptr(this->secSubsystemAppAPI, [&](std::shared_ptr<SecuritySubsystemAppAPI> sptr) {
        sptr->AppSecDataRequest(this->data_->appId, this->data_->sessionId, this->data_->cryptoHandle,
                data, signParams);
    });
}

ApplicationTLS::data_t::data_t(BaseTypes::Role role, BaseTypes::Socket sock, BaseTypes::AppId appId, BaseTypes::SessionId sessionId, BaseTypes::CryptomaterialHandle cryptoHandle)
: role(role)
, sock(sock)
, appId(appId)
, sessionId(sessionId)
, cryptoHandle(cryptoHandle)
{
}