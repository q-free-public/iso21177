#include "Asn1Helpers.hh"

#include <array>

#include "Iso21177AccessControlPdu.h"
#include "OCTET_STRING.h"

std::vector<uint8_t> Asn1Helpers::Ieee1609Dot2UnsecuredFromBuffer(const std::vector<uint8_t> &data_input)
{
    std::array<uint8_t, 65535> buffer;

    Ieee1609Dot2Data_t ieee1609Dot2Data;
    memset(&ieee1609Dot2Data, 0, sizeof(ieee1609Dot2Data));

    ieee1609Dot2Data.protocolVersion = 0x03;
    ieee1609Dot2Data.content = static_cast<struct Ieee1609Dot2Content *>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    ieee1609Dot2Data.content->present = Ieee1609Dot2Content_PR_unsecuredData;
    OCTET_STRING_fromBuf(&ieee1609Dot2Data.content->choice.unsecuredData, (const char *)(data_input.data()), data_input.size());

    asn_enc_rval_t rval = oer_encode_to_buffer(&asn_DEF_Ieee1609Dot2Data, nullptr, &ieee1609Dot2Data, buffer.data(), buffer.size());
    std::vector<uint8_t> ret;
    if (rval.encoded < 0) {
        return ret;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ieee1609Dot2Data, &ieee1609Dot2Data);


    ret.assign(buffer.begin(), buffer.begin() + rval.encoded);
    return ret;
}
