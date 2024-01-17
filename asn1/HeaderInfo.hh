#pragma once

#include <vector>
#include <stdint.h>
#include <memory>

#include "Iso21177AccessControlPdu.h"
#include "asn1c_template_wrapper.hh"

namespace Asn1Helpers {

class HeaderInfo : public 
    asn1c_wrapper<HeaderInfo_t> {
public:
    HeaderInfo(BaseTypes::AID psid);
    HeaderInfo(BaseTypes::AID psid, BaseTypes::Time32 generationTime);
    HeaderInfo(const std::vector<uint8_t>& data);
};

} // namespace Asn1Helpers