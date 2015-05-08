CXX=g++
IDIR=-Ivdbd/include
SDIR=vdbd
LDIR=
BDIR=build
LIBS=-lm
CXXFLAGS=-c -Wall $(IDIR) -std=c++11
LDFLAGS=$(LIBS)

HEADERS=
SOURCES=vdbd.cpp

OBJECTS=$(patsubst %,$(BDIR)/%,$(SOURCES:.cpp=.o))
DEPENDS=$(patsubst %,$(BDIR)/%,$(HEADERS))

EXECUTABLE=vdbd

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

$(BDIR)/%.o: $(SDIR)/%.cpp
	$(CXX) $(CXXFLAGS) $< -o $@