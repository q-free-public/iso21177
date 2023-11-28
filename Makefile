
#CXXFLAGS += -g
OPENSSL_DIR=/home/michalk/src/qf/openssl/demos/rfc8902/../..
ASN1C_DIR=/home/michalk/src/qf/cits-iso21177-etsi-project/bin/asn1
CXXFLAGS += -I$(OPENSSL_DIR)/include -I$(ASN1C_DIR)
LDFLAGS += -L$(OPENSSL_DIR) -Wl,-rpath=$(OPENSSL_DIR) -L$(ASN1C_DIR) -Wl,-rpath=$(ASN1C_DIR)
LDLIBS += -lssl -lcrypto -lItsAsn

HEADERS := $(wildcard *.hh)
SOURCES := $(wildcard *.cpp)
TARGETS := $(shell grep -l "^int main" *.cpp)
SOURCES_NO_TARGETS := $(filter-out $(TARGETS),$(SOURCES))
# SOURCES := \
# 	ApplicationElementI.cpp \
# 	Example.cpp \
# 	ApplicationElementExample.cpp \
# 	SecuritySubsystemAppAPI.cpp \
# 	SecuritySubsystem.cpp \
# 	SecureSession.cpp \
# 	SecureSessionSecSubAPI.cpp

OBJECTS := $(patsubst %.cpp, %.o, $(SOURCES))
OBJECTS_NO_TARGETS := $(patsubst %.cpp, %.o, $(SOURCES_NO_TARGETS))

COMPILE.cpp = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@
LINK.o = $(CXX) $(LDFLAGS) $(OBJECTS_NO_TARGETS) $@.o -o $@ $(LDLIBS)

%.o: %.cpp
	$(COMPILE.cpp) $<

all: Example Example-debug ExampleTLS

Example-debug: $(SOURCES) $(OBJECTS)
	$(LINK.o)

Example: $(SOURCES) $(OBJECTS)
	$(LINK.o)

ExampleTLS: $(SOURCES) $(OBJECTS)
	$(LINK.o)

asn1cTest: $(SOURCES) $(OBJECTS)
	$(LINK.o)

run_example:
	-LD_LIBRARY_PATH=$(OPENSSL_DIR) ./Example

run_tls:
	-LD_LIBRARY_PATH=$(OPENSSL_DIR) ./ExampleTLS

clean:
	rm -rf *.o Example Example-debug