#pragma once

#include <vector>
#include <stdint.h>
#include <memory>

#include "Iso21177AccessControlPdu.h"
#include "asn1c_template_wrapper.hh"
#include "HeaderInfo.hh"

namespace Asn1Helpers {

class ToBeSignedData : public 
    asn1c_wrapper<ToBeSignedData_t> {
public:
    ToBeSignedData(Asn1Helpers::HeaderInfo&& hdrInfo, const std::vector<uint8_t>& data);
};

} // namespace Asn1Helpers