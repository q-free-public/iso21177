#pragma once

#include "SignerIdentifier.h"
#include "asn1c_template_wrapper.hh"
namespace Asn1Helpers {

class SignerIdentifier : public 
    asn1c_wrapper<SignerIdentifier_t> {
public:
    enum class type {NOTHING, DIGEST, CERTIFICATE, SELF };
    SignerIdentifier(std::integral_constant<type, type::DIGEST>,  const std::array<uint8_t, 8>& data);
    SignerIdentifier(const std::vector<uint8_t>& data);
    virtual const std::vector<uint8_t> getPayload() const;
};

} // namespace Asn1Helpers
