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

} // namespace Asn1Helpers