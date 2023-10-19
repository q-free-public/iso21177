


#SOURCES := $(wildcard *.cpp)
SOURCES := Application.cpp Example.cpp ApplicationExample.cpp SecuritySubsystemAppAPI.cpp
OBJECTS := $(patsubst %.cpp, %.o, $(SOURCES))

COMPILE.cpp = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) -c -o $@
LINK.o = $(CXX) $(LDFLAGS) $(LDLIBS) $(OBJECTS) -o $@

%.o: %.cpp
	$(COMPILE.cpp) $<

example: $(SOURCES) $(OBJECTS)
	$(LINK.o)

clean:
	rm *.o
	rm example