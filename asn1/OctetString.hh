#pragma once

#include "OCTET_STRING.h"
#include "asn1c_template_wrapper.hh"
namespace Asn1Helpers {

class OctetString : public 
    asn1c_wrapper<OCTET_STRING_t> {
public:
    enum class type {DATA };
    OctetString(std::integral_constant<type, type::DATA>,  const std::vector<uint8_t>& data);
    OctetString(const std::vector<uint8_t>& data);
    virtual const std::vector<uint8_t> getPayload() const;
};

} // namespace Asn1Helpers
