#include "ToBeSignedData.hh"
#include "Ieee1609Dot2Data.hh"

namespace Asn1Helpers {

ToBeSignedData::ToBeSignedData(const std::vector<uint8_t>& payload)
: asn1c_wrapper(&asn_DEF_ToBeSignedData)
{
    data_->payload = static_cast<struct SignedDataPayload *>(calloc(1, sizeof(struct SignedDataPayload)));
    data_->payload->data = static_cast<Ieee1609Dot2Data_t *>(calloc(1, sizeof(Ieee1609Dot2Data_t)));

    Ieee1609Dot2Data payload_wrapped(std::integral_constant<Ieee1609Dot2Data::type, Ieee1609Dot2Data::type::UnsecuredData>{}, payload);
    payload_wrapped.debugPrint();
    std::vector<uint8_t> payload_wrapped_buffer = payload_wrapped.getEncodedBuffer();
    std::cerr << hex_string(payload_wrapped_buffer) << "\n";

    asn_dec_rval_t rval = oer_decode(0, &asn_DEF_Ieee1609Dot2Data, (void **)(&data_->payload->data), 
            payload_wrapped_buffer.data(), payload_wrapped_buffer.size());

    if (rval.consumed != payload_wrapped_buffer.size()) {
        throw std::runtime_error("failed to fill toBeSignedPayload " + std::to_string(rval.code)  + " consumed " + std::to_string(rval.consumed) + " / " + std::to_string(payload_wrapped_buffer.size()));
    }
}

} // namespace Asn1Helpers