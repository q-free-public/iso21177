#include "APDU.hh"

namespace Asn1Helpers {

APDU::APDU(
        std::integral_constant<type, type::DATA>,
        const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Apdu)
{
    OCTET_STRING_fromBuf(data_.get(), (const char *)(data.data()), data.size());
}

APDU::APDU(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Apdu, data)
{
}

const std::vector<uint8_t> APDU::getPayload() const
{
    return std::vector<uint8_t>(data_->buf, data_->buf + data_->size);
}

} // namespace Asn1Helpers