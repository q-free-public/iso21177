#include "HeaderInfo.hh"
#include "constr_TYPE.h"

#include "HeaderInfo.h"
#include "Time64.h"

#include <array>
#include <functional>

namespace Asn1Helpers {

HeaderInfo::HeaderInfo(BaseTypes::AID psid)
: asn1c_wrapper(&asn_DEF_HeaderInfo)
{
    data_->psid = psid;
}

HeaderInfo::HeaderInfo(BaseTypes::AID psid, uint64_t generationTime)
: asn1c_wrapper(&asn_DEF_HeaderInfo)
{
    data_->psid = psid;
    data_->generationTime = static_cast<Time64_t *>(calloc(1, sizeof(Time64_t)));
    asn_uint642INTEGER(data_->generationTime, generationTime);
}

HeaderInfo::HeaderInfo(const std::vector<uint8_t>& data)
: asn1c_wrapper(&asn_DEF_HeaderInfo, data) 
{
}

} // namespace Asn1Helpers