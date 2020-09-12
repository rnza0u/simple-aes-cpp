cmake_minimum_required(VERSION 3.18)

project(simple-aes-cpp)

add_library(${PROJECT_NAME} "")

target_sources(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/AES.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/Pkcs7Padding.cpp
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/src/AES.h
        ${CMAKE_CURRENT_LIST_DIR}/src/Pkcs7Padding.h
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}
)