
COMPILER=g++
COMPILE_FLAGS=-I./.include -I../nextcash/.include -Isecp256k1/include -pthread -std=c++11 -Wall -DDISABLE_ADDRESSES
# To Turn profiler on add this to the end of COMPILE_FLAGS : -DPROFILER_ON
LIBRARY_PATHS=-L../nextcash -Lsecp256k1/.libs
LIBRARIES=-lnextcash -lsecp256k1
DEBUG_LIBRARIES=-lnextcash.debug -lsecp256k1
LINK_FLAGS=-pthread
HEADER_FILES=$(wildcard src/*.hpp)
SOURCE_FILES=$(wildcard src/*.cpp)
OBJECT_DIRECTORY=.objects
HEADER_DIRECTORY=.include
OBJECTS=$(patsubst %.cpp,${OBJECT_DIRECTORY}/%.o,${SOURCE_FILES})
DEBUG_OBJECTS=$(patsubst %.cpp,${OBJECT_DIRECTORY}/%.o.debug,${SOURCE_FILES})
OUTPUT=bitcoin

.PHONY: list clean test release debug

list:
	@echo Headers : $(HEADER_FILES)
	@echo Sources : $(SOURCE_FILES)
	@echo Run Options :
	@echo "  make build_secp256k1    # Run tests"
	@echo "  make debug   # Build exe with gdb info"
	@echo "  make release # Build release exe"
	@echo "  make test    # Run tests"
	@echo "  make clean   # Remove all generated files"

build_secp256k1:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tBUILDING secp256k1"
	@echo ----------------------------------------------------------------------------------------------------
	@cd secp256k1; ./autogen.sh; ./configure; make
	@touch build_secp256k1

test_secp256k1:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tTESTING secp256k1"
	@echo ----------------------------------------------------------------------------------------------------
	@cd secp256k1; ./tests

headers:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tCOPYING HEADERS"
	@echo ----------------------------------------------------------------------------------------------------
	@mkdir -vp ${HEADER_DIRECTORY}
	@cp -v src/*.hpp ${HEADER_DIRECTORY}/

${OBJECT_DIRECTORY}:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tCREATING OBJECT DIRECTORY"
	@echo ----------------------------------------------------------------------------------------------------
	@mkdir -vp ${OBJECT_DIRECTORY}/src

${OBJECT_DIRECTORY}/.headers: $(HEADER_FILES) | ${OBJECT_DIRECTORY}
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tHEADER(S) UPDATED $?"
	@echo ----------------------------------------------------------------------------------------------------
	@rm -vf ${OBJECT_DIRECTORY}/*.o
	@rm -vf ${OBJECT_DIRECTORY}/*/*.o
	@touch ${OBJECT_DIRECTORY}/.headers

${OBJECT_DIRECTORY}/.debug_headers: $(HEADER_FILES) | ${OBJECT_DIRECTORY}
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tHEADER(S) UPDATED $?"
	@echo ----------------------------------------------------------------------------------------------------
	@rm -vf ${OBJECT_DIRECTORY}/*.o.debug
	@rm -vf ${OBJECT_DIRECTORY}/*/*.o.debug
	@touch ${OBJECT_DIRECTORY}/.debug_headers

${OBJECT_DIRECTORY}/%.o: %.cpp | ${OBJECT_DIRECTORY}
	@echo "\033[0;32m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;32mCOMPILING RELEASE $<\033[0m"
	@echo "\033[0;32m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -o $@ $< ${COMPILE_FLAGS}

${OBJECT_DIRECTORY}/%.o.debug: %.cpp | ${OBJECT_DIRECTORY}
	@echo "\033[0;32m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;32mCOMPILING DEBUG $<\033[0m"
	@echo "\033[0;32m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -ggdb -o $@ $< ${COMPILE_FLAGS}

release: headers ${OBJECT_DIRECTORY}/.headers build_secp256k1 ${OBJECTS} main.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING RELEASE ${OUTPUT}\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -o ${OBJECT_DIRECTORY}/main.o main.cpp ${COMPILE_FLAGS}
	${COMPILER} ${OBJECTS} ${OBJECT_DIRECTORY}/main.o ${LIBRARY_PATHS} ${LIBRARIES} -o ${OUTPUT} ${LINK_FLAGS}
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

debug: headers ${OBJECT_DIRECTORY}/.debug_headers build_secp256k1 ${DEBUG_OBJECTS} main.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING DEBUG ${OUTPUT}\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -ggdb -o ${OBJECT_DIRECTORY}/main.o.debug main.cpp ${COMPILE_FLAGS}
	${COMPILER} ${DEBUG_OBJECTS} ${OBJECT_DIRECTORY}/main.o.debug ${LIBRARY_PATHS} ${DEBUG_LIBRARIES} -o ${OUTPUT}.debug ${LINK_FLAGS}
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

test: headers ${OBJECT_DIRECTORY}/.headers build_secp256k1 ${OBJECTS} bitcoin_test.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING TEST\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -o ${OBJECT_DIRECTORY}/test.o bitcoin_test.cpp ${COMPILE_FLAGS}
	${COMPILER} ${OBJECTS} ${OBJECT_DIRECTORY}/test.o ${LIBRARY_PATHS} ${LIBRARIES} -o test ${LINK_FLAGS}
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mTESTING\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@./test || echo "\n                                  \033[0;31m!!!!!  Tests Failed  !!!!!\033[0m"
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

all: clean release debug test

test.debug: headers ${OBJECT_DIRECTORY}/.debug_headers build_secp256k1 ${DEBUG_OBJECTS} bitcoin_test.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING DEBUG TEST\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -ggdb -o ${OBJECT_DIRECTORY}/test.o.debug bitcoin_test.cpp ${COMPILE_FLAGS}
	${COMPILER} ${DEBUG_OBJECTS} ${OBJECT_DIRECTORY}/test.o.debug ${LIBRARY_PATHS} ${LIBRARIES} -o test.debug ${LINK_FLAGS}
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"

clean:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tCLEANING"
	@echo ----------------------------------------------------------------------------------------------------
	@rm -vfr ${HEADER_DIRECTORY} ${OBJECT_DIRECTORY} test test.debug ${OUTPUT} ${OUTPUT}.debug
	@cd secp256k1; make clean
	@rm build_secp256k1
