#include "SignerIdentifier.hh"

namespace Asn1Helpers {
SignerIdentifier::SignerIdentifier(std::integral_constant<type, type::DIGEST>,  const std::array<uint8_t, 8>& data)
: asn1c_wrapper(&asn_DEF_SignerIdentifier) {
    data_->present = SignerIdentifier_PR_digest;
    OCTET_STRING_fromBuf(&data_->choice.digest, (const char *)(data.data()), data.size());
}

SignerIdentifier::SignerIdentifier(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_SignerIdentifier, data)
{
}

const std::vector<uint8_t> SignerIdentifier::getPayload() const
{
    // TODO: implement
    return std::vector<uint8_t>();
}

} // namespace Asn1Helpers