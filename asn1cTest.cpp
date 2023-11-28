#include "Iso21177AccessControlPdu.h"
#include "OCTET_STRING.h"

#include <vector>
#include <stdint.h>

typedef Iso21177AccessControlPdu_t asn1_iso21177_t;

void fill_Iso21177AccessControlPdu_t(Iso21177AccessControlPdu_t *pdu)
{
    memset(pdu, 0, sizeof(Iso21177AccessControlPdu_t));
    pdu->messageId = 1;
}

int main() {
    std::vector<uint8_t> data_input = {0x01, 0x02};

    Ieee1609Dot2Data_t ieee1609Dot2Data;
    memset(&ieee1609Dot2Data, 0, sizeof(ieee1609Dot2Data));

    ieee1609Dot2Data.protocolVersion = 0x03;
    ieee1609Dot2Data.content = static_cast<struct Ieee1609Dot2Content *>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    ieee1609Dot2Data.content->present = Ieee1609Dot2Content_PR_unsecuredData;
    OCTET_STRING_fromBuf(&ieee1609Dot2Data.content->choice.unsecuredData, reinterpret_cast<char *>(data_input.data()), data_input.size());

    xer_fprint(stdout, &asn_DEF_Ieee1609Dot2Data, &ieee1609Dot2Data);

    return 1;
}