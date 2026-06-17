cmake_minimum_required(VERSION 3.20)

project(js_memory_forensics_sandbox LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(JSFS_REQUIRE_V8 "Fail CMake configure when V8 is unavailable" OFF)
option(JSFS_BUILD_DOCS "Generate Doxygen HTML documentation during the default build" ON)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

set(V8_ROOT "" CACHE PATH "Optional V8 installation prefix")
set(JSFS_V8_HINTS)

if(V8_ROOT)
    list(APPEND JSFS_V8_HINTS "${V8_ROOT}")
endif()

find_program(BREW_EXECUTABLE brew)
if(BREW_EXECUTABLE)
    execute_process(
        COMMAND "${BREW_EXECUTABLE}" --prefix v8
        OUTPUT_VARIABLE JSFS_HOMEBREW_V8_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE JSFS_HOMEBREW_V8_RESULT
    )
    if(JSFS_HOMEBREW_V8_RESULT EQUAL 0 AND JSFS_HOMEBREW_V8_PREFIX)
        list(APPEND JSFS_V8_HINTS "${JSFS_HOMEBREW_V8_PREFIX}")
    endif()
endif()

if(PkgConfig_FOUND)
    pkg_check_modules(V8 QUIET v8)
endif()

set(JSFS_HAVE_V8 OFF)

if(V8_FOUND)
    set(JSFS_HAVE_V8 ON)
    message(STATUS "Found V8 through pkg-config")
else()
    if(JSFS_V8_HINTS)
        find_path(V8_INCLUDE_DIR v8.h HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec/include include NO_DEFAULT_PATH)
        find_path(V8_PLATFORM_INCLUDE_DIR libplatform/libplatform.h HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec/include include NO_DEFAULT_PATH)
        find_library(V8_LIBRARY NAMES v8_monolith v8 HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_BASE_LIBRARY NAMES v8_libbase HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_PLATFORM_LIBRARY NAMES v8_libplatform HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_ABSL_LIBRARY NAMES third_party_abseil-cpp_absl HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_ICUI18N_LIBRARY NAMES third_party_icu_icui18n HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_ICUUC_LIBRARY NAMES icuuc HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_PARTITION_BASE_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_base HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_PARTITION_CORE_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_core HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
        find_library(V8_PARTITION_SHIM_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_shim HINTS ${JSFS_V8_HINTS} PATH_SUFFIXES libexec lib NO_DEFAULT_PATH)
    endif()

    find_path(V8_INCLUDE_DIR v8.h PATH_SUFFIXES include include/node libexec/include)
    find_path(V8_PLATFORM_INCLUDE_DIR libplatform/libplatform.h PATH_SUFFIXES include include/node libexec/include)
    find_library(V8_LIBRARY NAMES v8_monolith v8 node PATH_SUFFIXES lib libexec)
    find_library(V8_BASE_LIBRARY NAMES v8_libbase PATH_SUFFIXES lib libexec)
    find_library(V8_PLATFORM_LIBRARY NAMES v8_libplatform PATH_SUFFIXES lib libexec)
    find_library(V8_ABSL_LIBRARY NAMES third_party_abseil-cpp_absl PATH_SUFFIXES lib libexec)
    find_library(V8_ICUI18N_LIBRARY NAMES third_party_icu_icui18n PATH_SUFFIXES lib libexec)
    find_library(V8_ICUUC_LIBRARY NAMES icuuc PATH_SUFFIXES lib libexec)
    find_library(V8_PARTITION_BASE_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_base PATH_SUFFIXES lib libexec)
    find_library(V8_PARTITION_CORE_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_core PATH_SUFFIXES lib libexec)
    find_library(V8_PARTITION_SHIM_LIBRARY NAMES third_party_partition_alloc_src_partition_alloc_allocator_shim PATH_SUFFIXES lib libexec)

    if(V8_INCLUDE_DIR AND V8_LIBRARY)
        set(JSFS_HAVE_V8 ON)
        message(STATUS "Found V8 headers and library manually")
    endif()
endif()

if(JSFS_REQUIRE_V8 AND NOT JSFS_HAVE_V8)
    message(FATAL_ERROR
        "V8 was not found. Install V8/libv8-dev or pass V8_INCLUDE_DIR and V8_LIBRARY."
    )
endif()

add_library(jsfs_core
    src/base64.cpp
    src/memory_dumper.cpp
    src/string_finder.cpp
)

target_include_directories(jsfs_core PUBLIC src)
target_compile_features(jsfs_core PUBLIC cxx_std_20)

if(UNIX AND NOT APPLE)
    target_compile_definitions(jsfs_core PUBLIC JSFS_LINUX=1)
endif()

if(JSFS_HAVE_V8)
    add_library(jsfs_runtime src/js_sandbox.cpp)
    target_compile_definitions(jsfs_runtime PUBLIC
        JSFS_HAVE_V8=1
        V8_31BIT_SMIS_ON_64BIT_ARCH
        V8_COMPRESS_POINTERS
    )

    if(V8_FOUND)
        target_include_directories(jsfs_runtime PRIVATE ${V8_INCLUDE_DIRS})
        target_compile_options(jsfs_runtime PRIVATE ${V8_CFLAGS_OTHER})
        target_link_directories(jsfs_runtime PRIVATE ${V8_LIBRARY_DIRS})
        target_link_libraries(jsfs_runtime PRIVATE ${V8_LIBRARIES})
    else()
        target_include_directories(jsfs_runtime PRIVATE ${V8_INCLUDE_DIR})
        if(V8_PLATFORM_INCLUDE_DIR)
            target_include_directories(jsfs_runtime PRIVATE ${V8_PLATFORM_INCLUDE_DIR})
        endif()
        target_link_libraries(jsfs_runtime PRIVATE ${V8_LIBRARY})
        foreach(extra_v8_library IN ITEMS
            V8_BASE_LIBRARY
            V8_PLATFORM_LIBRARY
            V8_ABSL_LIBRARY
            V8_ICUI18N_LIBRARY
            V8_ICUUC_LIBRARY
            V8_PARTITION_BASE_LIBRARY
            V8_PARTITION_CORE_LIBRARY
            V8_PARTITION_SHIM_LIBRARY
        )
            if(${extra_v8_library})
                target_link_libraries(jsfs_runtime PRIVATE ${${extra_v8_library}})
            endif()
        endforeach()
        get_filename_component(JSFS_V8_LIBRARY_DIR "${V8_LIBRARY}" DIRECTORY)
    endif()
else()
    add_library(jsfs_runtime src/js_sandbox_stub.cpp)
    message(WARNING "V8 not found: js-memory-sandbox will build with a diagnostic stub")
endif()

target_link_libraries(jsfs_runtime PUBLIC jsfs_core PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

add_executable(js-memory-sandbox src/main.cpp)
target_link_libraries(js-memory-sandbox PRIVATE jsfs_runtime)
if(JSFS_V8_LIBRARY_DIR)
    set_target_properties(js-memory-sandbox PROPERTIES BUILD_RPATH "${JSFS_V8_LIBRARY_DIR}")
endif()

enable_testing()

add_executable(jsfs-tests tests/test_core.cpp)
target_link_libraries(jsfs-tests PRIVATE jsfs_core)

set(JSFS_TEST_CASES
    base64_payload
    base64_whitespace
    base64_rejects_malformed_input
    maps_parser_valid_line
    maps_parser_rejects_bad_lines
    read_maps_file
    suspicious_filter
    string_extraction_ascii_and_utf16
    tracked_value_locations
    extraction_errors
)

foreach(test_case IN LISTS JSFS_TEST_CASES)
    add_test(NAME ${test_case} COMMAND jsfs-tests ${test_case})
endforeach()

if(JSFS_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/docs/api")
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_RECURSIVE NO)
    doxygen_add_docs(api-docs
        src
        README.md
        docs/user_guide.md
        ALL
        COMMENT "Generate HTML API documentation"
    )
endif()
