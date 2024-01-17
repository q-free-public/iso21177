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
}

VerificationStatus SecEntCommunicator::verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data &data)
{
    std::cerr << "Attempting uimplemented verifyIeee1609Dot2DataSigned \n";
    // TODO: implement
    std::vector<uint8_t> data_to_send_for_verification = data.getEncodedBuffer();
    return VerificationStatus::OK;
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

} // namespace SecEnt