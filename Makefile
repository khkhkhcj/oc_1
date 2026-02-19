CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -fPIC

LIB = libcaesar.so
TEST = test_program

all: $(LIB)

$(LIB): libcaesar.cpp libcaesar.h
	$(CXX) $(CXXFLAGS) -shared -o $(LIB) libcaesar.cpp

install: $(LIB)
	sudo cp $(LIB) /usr/local/lib/
	sudo ldconfig

test: $(TEST)
	./$(TEST) ./libcaesar.so A input.txt output.txt

$(TEST): test_program.cpp
	$(CXX) $(CXXFLAGS) -ldl -o $(TEST) test_program.cpp

clean:
	rm -f $(LIB) $(TEST) output.txt
