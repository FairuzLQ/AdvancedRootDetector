cmake_minimum_required(VERSION 3.22.1)
project(rootdetector)

add_library(rootdetector_native SHARED
    root_detector.cpp
)

target_link_libraries(rootdetector_native
    android
    log
)
