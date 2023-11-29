file(GLOB sources "*.cpp")
file(GLOB headers "*.hh")

include_directories(..)
include_directories(${ITS_ASN1C_PATH})

add_library(asn1 ${sources} ${headers})
target_link_libraries(asn1 ${ITS_ASN1_LIBRARY})