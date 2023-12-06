#pragma once

#include "../asn1/Ieee1609Dot2Data.hh"

namespace SecEnt {
    enum class VerificationStatus {
        OK,
        FAILED,
    };

    enum class SigningStatus {
        OK,
        FAILED
    };

    VerificationStatus verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data& data);
    SigningStatus signData(const std::vector<uint8_t>& input_payload, Asn1Helpers::Ieee1609Dot2Data& signed_data);

}