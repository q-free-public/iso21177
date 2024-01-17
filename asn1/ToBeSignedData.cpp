#include "ToBeSignedData.hh"
#include "Ieee1609Dot2Data.hh"

namespace Asn1Helpers {

ToBeSignedData::ToBeSignedData(
    Asn1Helpers::HeaderInfo&& hdrInfo,
    const std::vector<uint8_t>& payload)
: asn1c_wrapper(&asn_DEF_ToBeSignedData)
{
    this->setElement(&data_->headerInfo, std::move(hdrInfo));

    data_->payload = static_cast<struct SignedDataPayload *>(calloc(1, sizeof(struct SignedDataPayload)));
    data_->payload->data = static_cast<Ieee1609Dot2Data_t *>(calloc(1, sizeof(Ieee1609Dot2Data_t)));
    Ieee1609Dot2Data payload_wrapped(std::integral_constant<Ieee1609Dot2Data::type, Ieee1609Dot2Data::type::UnsecuredData>{}, payload);
    this->setElement(data_->payload->data, std::move(payload_wrapped));
}

} // namespace Asn1Helpers