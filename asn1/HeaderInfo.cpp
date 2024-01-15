#include "HeaderInfo.hh"
#include "constr_TYPE.h"

#include <array>
#include <functional>

namespace Asn1Helpers {

HeaderInfo::HeaderInfo(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_HeaderInfo, data)
{
}

} // namespace Asn1Helpers