#include "sec_ent_api.hh"

#include "asn1/SignerIdentifier.hh"
#include "sec_ent_messages.hh"

namespace SecEnt
{
    
VerificationStatus verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data &data)
{
    // TODO: implement
    std::vector<uint8_t> data_to_send_for_verification = data.getEncodedBuffer();
    return VerificationStatus::OK;
}

SigningStatus signData(const std::vector<uint8_t> &input_payload, Asn1Helpers::Ieee1609Dot2Data &signed_data)
{
    //TODO: implement
    Asn1Helpers::SignerIdentifier signer({0x01, 0x02});
    sec_ent_msg_sign_req req(signer, input_payload);

    // sec_ent_msg_sign_reply repl;
    // signed_data = repl.signed_data;
    return SigningStatus::OK;
}

} // namespace SecEnt