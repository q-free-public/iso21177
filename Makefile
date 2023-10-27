
#CXXFLAGS += -g


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
LINK.o = $(CXX) $(LDFLAGS) $(LDLIBS) $(OBJECTS_NO_TARGETS) $@.o -o $@

%.o: %.cpp
	$(COMPILE.cpp) $<

all: Example Example-debug

Example-debug: $(SOURCES) $(OBJECTS)
	$(LINK.o)

Example: $(SOURCES) $(OBJECTS)
	$(LINK.o)

clean:
	rm -rf *.o example