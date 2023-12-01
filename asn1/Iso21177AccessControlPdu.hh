#pragma once

#include "AccessControl.h"
#include "asn1c_template_wrapper.hh"

namespace Asn1Helpers {

class Iso21177AccessControlPdu : public 
    asn1c_wrapper<Iso21177AccessControlPdu_t> {
public:
    Iso21177AccessControlPdu(const std::vector<uint8_t>& data);
    virtual const std::vector<uint8_t> getPayload() const;
};

} // namespace Asn1Helpers