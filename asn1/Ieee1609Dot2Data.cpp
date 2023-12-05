#include "Ieee1609Dot2Data.hh"
#include "constr_TYPE.h"

#include <array>
#include <functional>

namespace Asn1Helpers {

Ieee1609Dot2Data::Ieee1609Dot2Data(std::integral_constant<type, type::UnsecuredData> i, const std::vector<uint8_t> &data_input)
: asn1c_wrapper(&asn_DEF_Ieee1609Dot2Data)
{
    data_->protocolVersion = 0x03;
    data_->content = static_cast<struct Ieee1609Dot2Content *>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    data_->content->present = Ieee1609Dot2Content_PR_unsecuredData;
    OCTET_STRING_fromBuf(&data_->content->choice.unsecuredData, (const char *)(data_input.data()), data_input.size());
}

Ieee1609Dot2Data::Ieee1609Dot2Data(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Ieee1609Dot2Data, data)
{
}

Ieee1609Dot2Data::type Ieee1609Dot2Data::getType() const
{
    switch (data_->content->present) {
    case Ieee1609Dot2Content_PR_unsecuredData:
        return type::UnsecuredData;
    case Ieee1609Dot2Content_PR_signedData:
        return type::SignedData;
    case Ieee1609Dot2Content_PR_encryptedData:
        return type::EncryptedData;
    case Ieee1609Dot2Content_PR_signedCertificateRequest:
        return type::SignedCertificateRequest;
    case Ieee1609Dot2Content_PR_signedX509CertificateRequest:
        return type::SignedX509CertificateRequest;
    default:
        return type::NOTHING;
    }
}

const std::vector<uint8_t> Ieee1609Dot2Data::getPayload() const
{
    std::vector<uint8_t> ret;

    switch (getType()) {
    case type::UnsecuredData:
    {
        std::array<uint8_t, 65535> buffer;
        asn_enc_rval_t rval = oer_encode_to_buffer(&asn_DEF_Opaque, nullptr,
            &data_->content->choice.unsecuredData, buffer.data(), buffer.size());
        if (rval.encoded < 0) {
            return ret;
        }
        ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
        break;
    }
    case type::SignedData: 
    {
        std::array<uint8_t, 65535> buffer;
        asn_enc_rval_t rval = oer_encode_to_buffer(&asn_DEF_SignedData, nullptr,
            data_->content->choice.signedData, buffer.data(), buffer.size());
        if (rval.encoded < 0) {
            return ret;
        }
        ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
        break;
    }
    //TODO: implement other types here
    default:
        break;
    }
    return ret;

}

} // namespace Asn1Helpers