cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(BASE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC_DIR ${BASE_PATH}/src)
set(INCLUDE_PATH ${BASE_PATH}/include)
set(BUILD_DIR ${BASE_PATH}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR}/bin)

set(SOURCES 
        ${SRC_DIR}/main.cpp)

include_directories(${INCLUDE_PATH})

project(OpenSSL_example)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} crypto ssl)
