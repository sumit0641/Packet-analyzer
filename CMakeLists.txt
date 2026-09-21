cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0 LANGUAGES NONE)

set(JAVA_SOURCES
    ${CMAKE_SOURCE_DIR}/include/connection_tracker.java
    ${CMAKE_SOURCE_DIR}/include/dpi_engine.java
    ${CMAKE_SOURCE_DIR}/include/fast_path.java
)

add_custom_target(packet_analyzer SOURCES ${JAVA_SOURCES})
