CXX=g++
IDIR=-Ivdbd/include
SDIR=vdbd
LDIR=
ODIR=build
BDIR=bin
LIBS=-lm
CXXFLAGS=-c -Wall $(IDIR) -std=c++11
LDFLAGS=$(LIBS)

HEADERS=
SOURCES=vdbd.cpp

OBJECTS=$(patsubst %,$(ODIR)/%,$(SOURCES:.cpp=.o))
DEPENDS=$(patsubst %,$(ODIR)/%,$(HEADERS))

EXECUTABLE=$(BDIR)/vdbd

all: DIRS $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

.PHONY: clean run

ifeq ($(OS),Windows_NT)

DIRS:
	if not exist $(ODIR) mkdir $(ODIR)
	if not exist $(BDIR) mkdir $(BDIR)

clean:
	cd $(ODIR) && del /Q /S *.o
	cd $(BDIR) && del /Q /S *.exe

run: $(EXECUTABLE)
	$(EXECUTABLE).exe

else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)

DIRS:
	mkdir -p $(ODIR) $(BDIR)

clean:
	rm $(ODIR)/*.o $(BDIR)/*.exe

    endif
    ifeq ($(UNAME_S),Darwin)

run: $(EXECUTABLE)
	$(EXECUTABLE)

DIRS:
	mkdir -p $(ODIR) $(BDIR)

clean:
	rm $(ODIR)/*.o $(BDIR)/*.exe

    endif
endif
