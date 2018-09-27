# ----- ----- STD COMPILATION OPTIONS ----- ----- #
CXX            = g++
VERSION        = -std=c++11
OPTIMIZE_FLAGS = -O0 -finline-functions -g
CXXFLAGS       = -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-array-bounds -g
LIBS           = -lbcc
# INCLUDES     = unused
TARGET         = ebpflow
# OBJS         = unused
USR_HEADERS    = 


# ----- ----- PHONY TARGETS ----- ----- #
.PHONY: all clean cleanall distclean install uninstall


# ----- ----- STD RULES ----- ----- #
# Builds the project
all: $(TARGET)
# Cleans intermediate files
clean:
	-rm -fr *.o *~ *.dSYM callgrind.out.*
# Cleans all the project
cleanall: clean
	-rm -fr $(TARGET) *.d


# ----- ----- GENERIC RULES ----- ----- #
# Standard c++ file compilation
%.o: %.cpp %.h
	$(CXX) $(VERSION) $(CFLAGS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -c -o $@ $< $(INCLUDES)


# ----- ----- FINAL OBJECT ----- ----- #
ebpflow: ebpflow.cpp $(OBJS) $(USR_HEADERS)
	$(CXX) $(VERSION) $(CFLAGS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -o $@ $< $(OBJS) $(INCLUDES) $(LIBS)


