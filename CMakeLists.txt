cmake_minimum_required(VERSION 3.24)
project(UniversalCombatArbiter VERSION 0.1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Keep the CI build small and focused on Skyrim SE/AE (1.6.1170 included).
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ENABLE_SKYRIM_SE ON CACHE BOOL "" FORCE)
set(ENABLE_SKYRIM_AE ON CACHE BOOL "" FORCE)
set(ENABLE_SKYRIM_VR OFF CACHE BOOL "" FORCE)
set(COMMONLIB_ENABLE_IPO OFF CACHE BOOL "" FORCE)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/extern/CommonLibSSE-NG/CMakeLists.txt")
    message(FATAL_ERROR "CommonLibSSE-NG not found. The GitHub Actions workflow downloads it automatically.")
endif()

add_subdirectory(extern/CommonLibSSE-NG CommonLibSSE-NG EXCLUDE_FROM_ALL)
include("${CMAKE_CURRENT_SOURCE_DIR}/extern/CommonLibSSE-NG/cmake/CommonLibSSE.cmake")

add_commonlibsse_plugin(UniversalCombatArbiter
    NAME "UniversalCombatArbiter"
    AUTHOR "OpenAI proof-of-concept"
    VERSION ${PROJECT_VERSION}
    USE_ADDRESS_LIBRARY
    SOURCES
        src/main.cpp
        src/PCH.h
)

target_precompile_headers(UniversalCombatArbiter PRIVATE src/PCH.h)
target_compile_features(UniversalCombatArbiter PRIVATE cxx_std_23)
