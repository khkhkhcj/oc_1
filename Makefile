CXX      = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++17 -pthread
TARGET   = secure_copy
SRCS     = secure_copy.cpp lib.cpp

all: $(TARGET)

$(TARGET): $(SRCS) lib.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET) *.enc *.log *.img

.PHONY: all clean
