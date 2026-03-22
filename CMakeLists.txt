cmake_minimum_required(VERSION 3.14)
project(authcord-example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libcurl
find_package(CURL REQUIRED)

# Find nlohmann/json (install via vcpkg, conan, or system package manager)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Example executable
add_executable(authcord_example examples/basic.cpp)

target_include_directories(authcord_example PRIVATE include)

target_link_libraries(authcord_example
    PRIVATE
        CURL::libcurl
        nlohmann_json::nlohmann_json
)
