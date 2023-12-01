#pragma once

#include "Apdu.h"
#include "asn1c_template_wrapper.hh"
namespace Asn1Helpers {

class APDU : public 
    asn1c_wrapper<Apdu_t> {
public:
    APDU(const std::vector<uint8_t>& data);
    virtual const std::vector<uint8_t> getPayload() const;
};

} // namespace Asn1Helpers
