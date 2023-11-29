#pragma once

#include <vector>
#include <stdint.h>
#include <memory>

#include "Iso21177AccessControlPdu.h"

class Ieee1609Dot2DataUnsecured {
public:
    Ieee1609Dot2DataUnsecured(const std::vector<uint8_t>& data);
    ~Ieee1609Dot2DataUnsecured();
    std::vector<uint8_t> getEncodedBuffer();
    void debugPrint();

private:
    std::unique_ptr<Ieee1609Dot2Data_t> asn1c_data_;
};