#include "Ieee1609Dot2DataUnsecured.hh"
#include "constr_TYPE.h"

#include <array>
#include <functional>

Ieee1609Dot2DataUnsecured::Ieee1609Dot2DataUnsecured(const std::vector<uint8_t> &data_input)
{
    asn1c_data_ = std::unique_ptr<Ieee1609Dot2Data_t>(
            static_cast<Ieee1609Dot2Data_t *>(calloc(1, sizeof(Ieee1609Dot2Data_t)))
    );
    memset(asn1c_data_.get(), 0, sizeof(Ieee1609Dot2Data_t));

    asn1c_data_->protocolVersion = 0x03;
    asn1c_data_->content = static_cast<struct Ieee1609Dot2Content *>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    asn1c_data_->content->present = Ieee1609Dot2Content_PR_unsecuredData;
    OCTET_STRING_fromBuf(&asn1c_data_->content->choice.unsecuredData, (const char *)(data_input.data()), data_input.size());
}

Ieee1609Dot2DataUnsecured::~Ieee1609Dot2DataUnsecured()
{
    if (asn1c_data_) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ieee1609Dot2Data, asn1c_data_.get());
    }
}

std::vector<uint8_t> Ieee1609Dot2DataUnsecured::getEncodedBuffer()
{
    std::array<uint8_t, 65535> buffer;

    asn_enc_rval_t rval = oer_encode_to_buffer(&asn_DEF_Ieee1609Dot2Data, nullptr,
            asn1c_data_.get(), buffer.data(), buffer.size());
    std::vector<uint8_t> ret;
    if (rval.encoded < 0) {
        return ret;
    }

    ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
    return ret;
}

void Ieee1609Dot2DataUnsecured::debugPrint()
{
    xer_fprint(stdout, &asn_DEF_Ieee1609Dot2Data, asn1c_data_.get());
}
