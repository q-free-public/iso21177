#include "OctetString.hh"

Asn1Helpers::OctetString::OctetString(std::integral_constant<type, type::DATA>, const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_OCTET_STRING)
{
    OCTET_STRING_fromBuf(data_.get(), (const char *)(data.data()), data.size());
}

Asn1Helpers::OctetString::OctetString(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_OCTET_STRING, data)
{
}

const std::vector<uint8_t> Asn1Helpers::OctetString::getPayload() const
{
    return std::vector<uint8_t>(data_->buf, data_->buf + data_->size);
}
