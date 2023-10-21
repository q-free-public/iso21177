
#CXXFLAGS += -g

SOURCES := $(wildcard *.cpp)
# SOURCES := \
# 	ApplicationElementI.cpp \
# 	Example.cpp \
# 	ApplicationElementExample.cpp \
# 	SecuritySubsystemAppAPI.cpp \
# 	SecuritySubsystem.cpp \
# 	SecureSession.cpp \
# 	SecureSessionSecSubAPI.cpp

OBJECTS := $(patsubst %.cpp, %.o, $(SOURCES))

COMPILE.cpp = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@
LINK.o = $(CXX) $(LDFLAGS) $(LDLIBS) $(OBJECTS) -o $@

%.o: %.cpp
	$(COMPILE.cpp) $<

example: $(SOURCES) $(OBJECTS)
	$(LINK.o)

clean:
	rm -rf *.o example