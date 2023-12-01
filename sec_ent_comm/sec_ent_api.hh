#pragma once

#include "../asn1/Ieee1609Dot2Data.hh"

namespace SecEnt {
    enum class VerificationStatus {
        VerificationOK,
        Failed,
    };

    VerificationStatus verifyIeee1609Dot2DataSigned(const Asn1Helpers::Ieee1609Dot2Data& data);

}