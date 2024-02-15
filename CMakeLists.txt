cmake_minimum_required(VERSION 3.5)
 
project(iso21177)

set(ITS_ASN1C_PATH asn1/asn1c/)
set(OPENSSL_PATH /home/michalk/src/qf/openssl/demos/rfc8902/../..)

find_library(
	ITS_ASN1_LIBRARY
	NAMES ItsAsn libItsAsn.a
    HINTS ${ITS_ASN1C_PATH}
)
include_directories(${ITS_ASN1C_PATH})

SET(ENV{OPENSSL_ROOT_DIR} ${OPENSSL_PATH})
FIND_PACKAGE(OpenSSL 3.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(asn1)
add_subdirectory(sec_ent_comm)
add_subdirectory(option_parsing)
add_subdirectory(AdaptorLayer)
add_subdirectory(SecureSession)
add_subdirectory(SecuritySubsystem)
add_subdirectory(Sockets)

include_directories(.)
file(GLOB sources "*.cpp")
file(GLOB headers "*.hh")
add_library(iso_code ${sources} ${headers})
target_link_libraries(iso_code option_parsing sec_ent asn1 adaptorLayer secureSession securitySubsystem sockets ${ITS_ASN1_LIBRARY})

add_executable(asn1cTest asn1cTest.cpp)
target_link_libraries(asn1cTest asn1 ${ITS_ASN1_LIBRARY})

add_executable(Example Example.cpp)
target_link_libraries(Example iso_code ${ITS_ASN1_LIBRARY} ${OPENSSL_LIBRARIES} )
add_executable(Example-debug Example-debug.cpp)
target_link_libraries(Example-debug iso_code ${ITS_ASN1_LIBRARY} ${OPENSSL_LIBRARIES})
add_executable(ExampleTLS ExampleTLS.cpp)
target_link_libraries(ExampleTLS iso_code ${ITS_ASN1_LIBRARY} ${OPENSSL_LIBRARIES})

add_executable(ExampleClientTLS ExampleClientTLS.cpp)
target_link_libraries(ExampleClientTLS iso_code ${ITS_ASN1_LIBRARY} ${OPENSSL_LIBRARIES})
add_executable(ExampleServerTLS ExampleServerTLS.cpp)
target_link_libraries(ExampleServerTLS iso_code ${ITS_ASN1_LIBRARY} ${OPENSSL_LIBRARIES})