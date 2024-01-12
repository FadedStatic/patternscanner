# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.24)

project ("patternscanner")

# Include sub-projects.
add_subdirectory ("scattern_panner")
add_subdirectory ("victim_app")