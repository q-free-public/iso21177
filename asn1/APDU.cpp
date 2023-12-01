#include "APDU.hh"

namespace Asn1Helpers {

APDU::APDU(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Apdu, data)
{
}

const std::vector<uint8_t> APDU::getPayload() const
{
    return std::vector<uint8_t>(data_->buf, data_->buf + data_->size);
}

} // namespace Asn1Helpers