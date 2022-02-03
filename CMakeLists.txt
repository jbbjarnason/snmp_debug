cmake_minimum_required(VERSION 3.22)
project(snmp_debug)

# Note: reference of snmp setup from https://github.com/higherorderfunctor/snmp-fetch/blob/master/CMakeLists.txt

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

include(ProcessorCount)
# increase install speed with parallel builds
ProcessorCount(N)
if(NOT N EQUAL 0)
    set(GIT_CONFIG submodule.fetchJobs=${N})
    set(MAKEFLAGS -j${N})
    set(CTEST_BUILD_FLAGS -j${N})
    set(ctest_test_args ${ctest_test_args} PARALLEL_LEVEL ${N})
endif()

include(ExternalProject)
# get, build, and install net-snmp
ExternalProject_Add(netsnmp
    GIT_REPOSITORY https://github.com/net-snmp/net-snmp
    GIT_TAG v5.9
    GIT_SHALLOW 1
    GIT_CONFIG ${GIT_CONFIG}
    CMAKE_ARGS
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    CONFIGURE_COMMAND ./configure --prefix=${CMAKE_BINARY_DIR} --with-defaults --enable-ucd-snmp-compatibility --disable-agent --disable-applications --disable-manuals --disable-scripts --disable-mibs --disable-mib-loading --enable-static --disable-shared --with-ldflags=-Bstatic
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} snmplib
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} installlocalheaders && cd snmplib && ${CMAKE_MAKE_PROGRAM} install
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
)

add_library(libnetsnmp STATIC IMPORTED)
set_target_properties(libnetsnmp PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/lib/libnetsnmp${CMAKE_STATIC_LIBRARY_SUFFIX}
)

add_executable(snmp_debug main.cpp)

target_link_libraries(snmp_debug
    PRIVATE
        libnetsnmp
        OpenSSL::Crypto
)
