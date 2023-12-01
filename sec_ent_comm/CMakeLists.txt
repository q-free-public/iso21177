file(GLOB sources "*.cpp")
file(GLOB headers "*.hh")

include_directories(..)
include_directories(${ITS_ASN1C_PATH})

add_library(sec_ent OBJECT ${sources} ${headers})
target_link_libraries(sec_ent)