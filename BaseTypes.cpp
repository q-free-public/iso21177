#include "BaseTypes.hh"

std::vector<uint8_t> parse_hex_string(const std::string& input) {
    std::stringstream ss;
	std::vector<uint8_t> ret;
	size_t written_count = 0;
	for (std::size_t i = 0; i < input.size(); i++) {
		if (input[i] == ':' || input[i] == ' ') {
			continue;
		}
		if (written_count % 2 == 0) {
			ss << ' ';
		}
		ss << input[i];
		written_count++;
	}

	unsigned int c;
	while (ss >> std::hex >> c) {
	    ret.push_back(c);
	}
	return ret;
}