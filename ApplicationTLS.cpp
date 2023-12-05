#include "ApplicationTLS.hh"

#include "Sockets/SocketTCP.hh"
#include "asn1/Ieee1609Dot2Data.hh"
#include "asn1/APDU.hh"

ApplicationTLS::ApplicationTLS()
: data_(nullptr)
{
}

void ApplicationTLS::AppSecConfigureConfirm(SecuritySubsystemAppAPI::AppSecConfigureConfirmResult)
{
}

void ApplicationTLS::AppSecStartSessionIndictation(const BaseTypes::AppId &, const BaseTypes::SessionId &)
{
}

void ApplicationTLS::AppSecDataConfirm(SecuritySubsystemAppAPI::AppSecDataConfirmResult, const BaseTypes::SignedData &)
{
}

void ApplicationTLS::AppALDataConfirm()
{
}

void ApplicationTLS::AppALDataIndication(const BaseTypes::AppId &appId, const BaseTypes::SessionId &sessionId, const BaseTypes::Data &data)
{
    
    std::cerr << "### Received data: " << hex_string(data) << "\n";
    Asn1Helpers::APDU apdu_parsed(data);
    Asn1Helpers::Ieee1609Dot2Data data_parsed(apdu_parsed.getPayload());
    data_parsed.debugPrint();
    std::vector<uint8_t> data_payload = data_parsed.getPayload();
    std::cerr << std::string(data_payload.begin(), data_payload.end()) << "\n";
    sendDataUnsecured(data_payload);
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
    std::cerr << "##########Session was deactivated!!!\n";
}

void ApplicationTLS::configureApp(BaseTypes::SessionId sessionId, BaseTypes::Role role)
{
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
        std::integral_constant<Asn1Helpers::Ieee1609Dot2Data::type, Asn1Helpers::Ieee1609Dot2Data::type::UnsecuredData>(), data
    ).getEncodedBuffer();
    std::vector<uint8_t> apdu_encap = Asn1Helpers::APDU(std::integral_constant<Asn1Helpers::APDU::type, Asn1Helpers::APDU::type::DATA>(), data_encap
    ).getEncodedBuffer();
    call_function_wptr(this->aLAppAPI, [&](std::shared_ptr<AdaptorLayerAppAPI> sptr) {
        sptr->AppALDataRequest(
            this->data_->appId,
            this->data_->sessionId,
            apdu_encap);
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