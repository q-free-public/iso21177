#pragma once

#include <vector>
#include <stdint.h>
#include <memory>

#include "Iso21177AccessControlPdu.h"
#include "asn1c_template_wrapper.hh"

namespace Asn1Helpers {

class Ieee1609Dot2Data : public 
    asn1c_wrapper<Ieee1609Dot2Data_t> {
public:
    enum class type {NOTHING, UnsecuredData, SignedData, EncryptedData, SignedCertificateRequest, SignedX509CertificateRequest};
    Ieee1609Dot2Data(std::integral_constant<type, type::NOTHING> i);
    Ieee1609Dot2Data(std::integral_constant<type, type::UnsecuredData> i, const std::vector<uint8_t>& data);
    Ieee1609Dot2Data(const std::vector<uint8_t>& data);
    type getType() const;
    virtual const std::vector<uint8_t> getPayload() const;
};

} // namespace Asn1Helpers