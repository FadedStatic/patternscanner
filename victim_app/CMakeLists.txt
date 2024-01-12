cmake_minimum_required (VERSION 3.24)
project(victim_app)

add_executable(victim_app main.cpp)
set_property(TARGET victim_app PROPERTY CXX_STANDARD 23)