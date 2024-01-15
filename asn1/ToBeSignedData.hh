#pragma once

#include <vector>
#include <stdint.h>
#include <memory>

#include "Iso21177AccessControlPdu.h"
#include "asn1c_template_wrapper.hh"

namespace Asn1Helpers {

class ToBeSignedData : public 
    asn1c_wrapper<ToBeSignedData_t> {
public:
    ToBeSignedData(const std::vector<uint8_t>& data);
};

} // namespace Asn1Helpers