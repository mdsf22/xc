cmake_minimum_required(VERSION 3.12)

# Set the project name
project(xc)
set(CMAKE_BUILD_TYPE Debug)
# Add a library target
find_package(LibXml2 REQUIRED)
find_package(CURL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
add_executable(xc
    main.cpp
    xe_client.cpp
)

# Link the library to the executable
target_include_directories(xc
    PUBLIC
    ${LIBXML2_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/../3rd/include)

target_link_directories(xc PUBLIC "${CMAKE_SOURCE_DIR}/../3rd/lib")
target_link_libraries(xc PUBLIC xenserver xml2 jsoncpp curl pthread)
configure_file(${CMAKE_SOURCE_DIR}/config.conf ${CMAKE_BINARY_DIR}/config.conf COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/backup_set.json ${CMAKE_BINARY_DIR}/backup_set.json COPYONLY)
