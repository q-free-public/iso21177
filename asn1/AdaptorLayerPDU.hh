#pragma once

#include <vector>
#include <stdint.h>

#include "Iso21177AdaptorLayerPdu.h"
#include "asn1c_template_wrapper.hh"


namespace Asn1Helpers {

class AdaptorLayerPdu : public 
        asn1c_wrapper<Iso21177AdaptorLayerPdu_t> {
public:
    enum class type { APDU, AccessControl, TlsClientMsg1, TlsServerMsg1, NOTHING };
    AdaptorLayerPdu(std::integral_constant<type, type::APDU> i, const std::vector<uint8_t>& data);
    AdaptorLayerPdu(const std::vector<uint8_t>& data);

    type getType() const;
    virtual const std::vector<uint8_t> getPayload() const;

private:

};

} // namespace Asn1Helpers