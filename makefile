
COMPILER=g++
COMPILE_FLAGS=-I./include -I../ArcMist/include -I../secp256k1/include -std=c++11 -Wall
# To disable Bitcoin Cash add this to the end if COMPILE_FLAGS : -DDISABLE_CASH
# To Turn profiler on add this to the end of the previous line -DPROFILER_ON
LIBRARY_PATHS=-L../ArcMist -L../secp256k1/.libs
LIBRARIES=-larcmist -lsecp256k1
DEBUG_LIBRARIES=-larcmist.debug -lsecp256k1
# secp256k1 lib Downloaded source from github, ran ./configure, found in .libs directory
LINK_FLAGS=-pthread
HEADER_FILES=$(wildcard src/*.hpp)
SOURCE_FILES=$(wildcard src/*.cpp)
OBJECT_DIRECTORY=.objects
HEADER_DIRECTORY=include
OBJECTS=$(patsubst %.cpp,${OBJECT_DIRECTORY}/%.o,${SOURCE_FILES})
DEBUG_OBJECTS=$(patsubst %.cpp,${OBJECT_DIRECTORY}/%.o.debug,${SOURCE_FILES})
OUTPUT=bitcoin

.PHONY: list clean test release debug

list:
	@echo Headers : $(HEADER_FILES)
	@echo Sources : $(SOURCE_FILES)
	@echo Run Options :
	@echo "  make test    # Run tests"
	@echo "  make debug   # Build exe with gdb info"
	@echo "  make release # Build release exe"
	@echo "  make clean   # Remove all generated files"

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

release: headers ${OBJECT_DIRECTORY}/.headers ${OBJECTS} main.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING RELEASE ${OUTPUT}\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -o ${OBJECT_DIRECTORY}/main.o main.cpp ${COMPILE_FLAGS}
	${COMPILER} ${OBJECTS} ${OBJECT_DIRECTORY}/main.o ${LIBRARY_PATHS} ${LIBRARIES} -o ${OUTPUT} ${LINK_FLAGS}
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

debug: headers ${OBJECT_DIRECTORY}/.debug_headers ${DEBUG_OBJECTS} main.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING DEBUG ${OUTPUT}\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -ggdb -o ${OBJECT_DIRECTORY}/main.o.debug main.cpp ${COMPILE_FLAGS}
	${COMPILER} ${DEBUG_OBJECTS} ${OBJECT_DIRECTORY}/main.o.debug ${LIBRARY_PATHS} ${DEBUG_LIBRARIES} -o ${OUTPUT}.debug ${LINK_FLAGS}
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

test: headers ${OBJECT_DIRECTORY}/.headers ${OBJECTS} test.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING TEST\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -o ${OBJECT_DIRECTORY}/test.o test.cpp ${COMPILE_FLAGS}
	${COMPILER} ${OBJECTS} ${OBJECT_DIRECTORY}/test.o ${LIBRARY_PATHS} ${LIBRARIES} -o test ${LINK_FLAGS}
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mTESTING\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@./test || echo "\n                                  \033[0;31m!!!!!  Tests Failed  !!!!!\033[0m"
	@echo "\033[0;34m----------------------------------------------------------------------------------------------------\033[0m"

all: clean release debug test

test.debug: headers ${OBJECT_DIRECTORY}/.debug_headers ${DEBUG_OBJECTS} test.cpp
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	@echo "\t\033[0;33mBUILDING DEBUG TEST\033[0m"
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"
	${COMPILER} -c -ggdb -o ${OBJECT_DIRECTORY}/test.o.debug test.cpp ${COMPILE_FLAGS}
	${COMPILER} ${DEBUG_OBJECTS} ${OBJECT_DIRECTORY}/test.o.debug ${LIBRARY_PATHS} ${DEBUG_LIBRARIES} -o test.debug ${LINK_FLAGS}
	@echo "\033[0;33m----------------------------------------------------------------------------------------------------\033[0m"

clean:
	@echo ----------------------------------------------------------------------------------------------------
	@echo "\tCLEANING"
	@echo ----------------------------------------------------------------------------------------------------
	@rm -vfr include ${OBJECT_DIRECTORY} test test.debug ${OUTPUT} ${OUTPUT}.debug
