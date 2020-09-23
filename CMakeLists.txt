cmake_minimum_required(VERSION 3.13)

project(simple-aes-cpp VERSION 1.0.0 DESCRIPTION "A simple and comprehensible AES implementation in C++")

add_library(${PROJECT_NAME}
    src/AES.cpp
    src/Pkcs7Padding.cpp
)

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER src/AES.h)

# Install library
install(TARGETS ${PROJECT_NAME} DESTINATION lib/${PROJECT_NAME})

# Install library headers
file(GLOB HEADERS src/include/*.h)
install(FILES ${HEADERS} DESTINATION include/${PROJECT_NAME})