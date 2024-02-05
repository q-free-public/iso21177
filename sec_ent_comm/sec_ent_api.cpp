#include "sec_ent_api.hh"

#include "asn1/SignerIdentifier.hh"
#include "asn1/ToBeSignedData.hh"
#include "sec_ent_messages.hh"
#include "sec_ent_comm.hh"

namespace SecEnt
{

SecEntCommunicator::SecEntCommunicator(const std::string address, int port)
: address_(address)
, port_(port)
, comm_(address, port)
{
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(address, "");
    for(boost::asio::ip::tcp::resolver::iterator i = resolver.resolve(query);
                            i != boost::asio::ip::tcp::resolver::iterator();
                            ++i)
    {
        boost::asio::ip::tcp::endpoint end = *i;
        address_ = end.address().to_string();
        // convert address to IP because calls to SSL_set_1609_sec_ent_addr require IP addr
        break;
    }
}

VerificationStatus SecEntCommunicator::verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data &data)
{
    sec_ent_msg_verify_req req(data);
    try {
        sec_ent_msg_verify_reply repl = send_recv<sec_ent_msg_verify_reply>(comm_.get_sock(), req);
        return VerificationStatus::OK;
    } catch (const std::exception& e) {
        std::cerr << "verification of signing failed: " << e.what() << "\n";
    }
    return VerificationStatus::FAILED;

}

SigningStatus SecEntCommunicator::signData(
        const Asn1Helpers::ToBeSignedData &tbsData,
        BaseTypes::CryptomaterialHandle cryptoHandle,
        Asn1Helpers::Ieee1609Dot2Data& signed_data)
{
    using SignerId = Asn1Helpers::SignerIdentifier;
    SignerId signer(std::integral_constant<SignerId::type, SignerId::type::DIGEST>{}, cryptoHandle);
    sec_ent_msg_sign_req req(signer, tbsData.getEncodedBuffer());

    try {
        sec_ent_msg_sign_reply repl = send_recv<sec_ent_msg_sign_reply>(comm_.get_sock(), req);
        signed_data = repl.getSignedData();
        return SigningStatus::OK;
    } catch (const std::exception& e) {
        std::cerr << "signing failed: " << e.what() << "\n";
    }
    return SigningStatus::FAILED;

}

BaseTypes::CryptomaterialHandle SecEntCommunicator::getCurrentATCert()
{
    sec_ent_get_at_req req;

    sec_ent_get_at_reply repl = send_recv<sec_ent_get_at_reply>(comm_.get_sock(), req);
    
    return BaseTypes::CryptomaterialHandle(repl.getATHash());
}

int SecEntCommunicator::getPort()
{
    return port_;
}

std::string SecEntCommunicator::getHost()
{
    return address_;
}

} // namespace SecEnt