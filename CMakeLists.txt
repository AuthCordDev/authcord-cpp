cmake_minimum_required(VERSION 3.14)
project(authcord-example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libcurl
find_package(CURL REQUIRED)

# Find nlohmann/json (install via vcpkg, conan, or system package manager)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Threads is needed by the heartbeat example (and recommended for any
# real consumer of the SDK because of HeartbeatLoop's std::thread).
find_package(Threads REQUIRED)

# Example executables
add_executable(authcord_example                examples/basic.cpp)
add_executable(authcord_heartbeat_example      examples/heartbeat.cpp)
add_executable(authcord_hwid_components_example examples/hwid_components.cpp)

target_include_directories(authcord_example                 PRIVATE include)
target_include_directories(authcord_heartbeat_example       PRIVATE include)
target_include_directories(authcord_hwid_components_example PRIVATE include)

set(_authcord_common_libs
    CURL::libcurl
    nlohmann_json::nlohmann_json
    Threads::Threads
)

target_link_libraries(authcord_example                 PRIVATE ${_authcord_common_libs})
target_link_libraries(authcord_heartbeat_example       PRIVATE ${_authcord_common_libs})
target_link_libraries(authcord_hwid_components_example PRIVATE ${_authcord_common_libs})

if(WIN32)
    # collect_hwid_components() needs Advapi32 for SID + registry APIs.
    target_link_libraries(authcord_hwid_components_example PRIVATE Advapi32)
    # The other examples don't strictly need Advapi32 today, but linking
    # it everywhere keeps the link line consistent if anyone calls
    # collect_hwid_components() from those binaries later.
    target_link_libraries(authcord_example           PRIVATE Advapi32)
    target_link_libraries(authcord_heartbeat_example PRIVATE Advapi32)
endif()
