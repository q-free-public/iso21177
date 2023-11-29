#include "Iso21177AccessControlPdu.h"
#include "OCTET_STRING.h"
#include "Asn1Helpers.hh"

#include <vector>
#include <stdint.h>
#include <iostream>

#include "BaseTypesGeneral.hh"
#include "asn1/Ieee1609Dot2DataUnsecured.hh"
#include "asn1/AdaptorLayerPDU.hh"

typedef Iso21177AccessControlPdu_t asn1_iso21177_t;

void fill_Iso21177AccessControlPdu_t(Iso21177AccessControlPdu_t *pdu)
{
    memset(pdu, 0, sizeof(Iso21177AccessControlPdu_t));
    pdu->messageId = 1;
}

int main() {
    std::vector<uint8_t> data_input = {0x01, 0x02};

    Ieee1609Dot2DataUnsecured ieee1609Dot2Data(data_input);
    ieee1609Dot2Data.debugPrint();
    std::cerr << "encoded Ieee1609Dot2DataUnsecured " << hex_string(ieee1609Dot2Data.getEncodedBuffer()) << "\n\n";

    std::integral_constant<AdaptorLayerPdu::type, AdaptorLayerPdu::type::APDU> val;
    AdaptorLayerPdu adaptorLayerPdu(std::integral_constant<AdaptorLayerPdu::type, AdaptorLayerPdu::type::APDU>(), data_input);
    adaptorLayerPdu.debugPrint();
    std::cerr << "encoded AdaptorLayerPdu " << hex_string(adaptorLayerPdu.getEncodedBuffer()) << "\n";
    std::cerr << "Data of AdaptorLayerPdu " << hex_string(adaptorLayerPdu.getPayload()) << "\n";
    return 1;
}