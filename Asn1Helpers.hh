#pragma once
#include <vector>
#include <stdint.h>


namespace Asn1Helpers {

std::vector<uint8_t> Ieee1609Dot2UnsecuredFromBuffer(const std::vector<uint8_t>& data);


} // namespace