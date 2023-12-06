file(GLOB sources "*.cpp")
file(GLOB headers "*.hh")

find_path(HAS_BOOST_ASIO "boost/asio.hpp")
if (NOT HAS_BOOST_ASIO)
    message(FATAL_ERROR "Boost asio missing")
endif()

include_directories(..)
include_directories(${ITS_ASN1C_PATH})

add_library(sec_ent OBJECT ${sources} ${headers})
target_link_libraries(sec_ent)