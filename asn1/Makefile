OPENSSL_DIR=/home/michalk/src/qf/openssl/demos/rfc8902/../..
ASN1C_DIR=/home/michalk/src/qf/cits-iso21177-etsi-project/bin/asn1
CXXFLAGS += -I$(OPENSSL_DIR)/include -I$(ASN1C_DIR)
LDFLAGS += -L$(OPENSSL_DIR) -Wl,-rpath=$(OPENSSL_DIR) -L$(ASN1C_DIR) -Wl,-rpath=$(ASN1C_DIR)
LDLIBS += -lssl -lcrypto -lItsAsn

HEADERS := $(wildcard *.hh)
SOURCES := $(wildcard *.cpp)
OBJECTS := $(patsubst %.cpp, %.o, $(SOURCES))

%.o: %.cpp
	$(COMPILE.cpp) $<

COMPILE.cpp = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@
LINK.o = $(CXX) $(LDFLAGS) $(OBJECTS_NO_TARGETS) $@.o -o $@ $(LDLIBS)