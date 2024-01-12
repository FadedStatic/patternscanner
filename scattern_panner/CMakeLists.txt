cmake_minimum_required (VERSION 3.24)
project(scattern_panner)

add_executable(scattern_panner example_main.cpp scanner.cpp scanner.hpp)
set_property(TARGET scattern_panner PROPERTY CXX_STANDARD 23)