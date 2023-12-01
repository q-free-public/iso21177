#include "Iso21177AccessControlPdu.hh"

namespace Asn1Helpers {

Asn1Helpers::Iso21177AccessControlPdu::Iso21177AccessControlPdu(const std::vector<uint8_t> &data)
: asn1c_wrapper(&asn_DEF_Iso21177AccessControlPdu, data)
{
}

const std::vector<uint8_t> Iso21177AccessControlPdu::getPayload() const
{
    // TODO: implement
    return std::vector<uint8_t>();
}

} // namespace Asn1Helpers