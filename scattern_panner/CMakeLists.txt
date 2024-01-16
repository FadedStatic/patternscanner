cmake_minimum_required (VERSION 3.24)
project(scattern_panner)

# add_executable(scattern_panner example_main.cpp scanner.cpp scanner.hpp) # uncomment this if ur making it an executable
add_library(scattern_panner SHARED example_main.cpp scanner.cpp scanner.hpp) # uncomment this if ur making it a dll
set_property(TARGET scattern_panner PROPERTY CXX_STANDARD 23)