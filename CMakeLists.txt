# cmake_minimum_required(VERSION <specify CMake version here>)
project(tls_decrypt C)

set(CMAKE_C_STANDARD 11)

add_executable(tls_decrypt main.c tls_handler.c utils.c utils.h)

target_link_libraries(tls_decrypt ssl crypto)