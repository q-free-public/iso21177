file(GLOB sources "*.cpp")
file(GLOB headers "*.hh")

FIND_PACKAGE( Boost 1.71 COMPONENTS program_options)
if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost program options missing")
else()
    INCLUDE_DIRECTORIES(SYSTEM ${Boost_INCLUDE_DIR})
    message(STATUS "System provided boost found ${Boost_INCLUDE_DIR}")
    SET(BOOST_PROGRAM_OPTIONS_LIB -lboost_program_options)
endif()

include_directories(..)
include_directories(${ITS_ASN1C_PATH})

add_library(option_parsing OBJECT ${sources} ${headers})
target_link_libraries(option_parsing ${BOOST_PROGRAM_OPTIONS_LIB})