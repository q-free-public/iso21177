#pragma once

#include "BaseTypesGeneral.hh"
#include "BaseTypesSocket.hh"

std::vector<uint8_t> parse_hex_string(const std::string& input);

template <std::size_t N>
std::array<uint8_t, N> array_from_vector(const std::vector<uint8_t>& vec) {
    std::array<uint8_t, N> arr;
    std::copy_n(vec.begin(), std::min(N, vec.size()), arr.begin());
    return arr;
}

template <std::size_t N>
std::array<uint8_t, N> parse_hex_array(const std::string& input) {
    return array_from_vector<N>(parse_hex_string(input));
}
