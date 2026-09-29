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

set(_authcord_common_libs
    CURL::libcurl
    nlohmann_json::nlohmann_json
    Threads::Threads
)

if(WIN32)
    # collect_hwid_components() needs Advapi32 for SID + registry APIs;
    # hosted_login() needs ws2_32 (loopback listener), shell32 (opens the
    # browser) and bcrypt (PKCE randomness). MSVC picks these up from the
    # header's #pragma comment(lib); MinGW needs them on the link line.
    list(APPEND _authcord_common_libs Advapi32 ws2_32 shell32 bcrypt)
endif()

# Example executables
add_executable(authcord_example                  examples/basic.cpp)
add_executable(authcord_heartbeat_example        examples/heartbeat.cpp)
add_executable(authcord_hwid_components_example  examples/hwid_components.cpp)
add_executable(authcord_hosted_login_example     examples/hosted_login.cpp)

set(_authcord_targets
    authcord_example
    authcord_heartbeat_example
    authcord_hwid_components_example
    authcord_hosted_login_example
)

# Tests: build, then run `ctest` from the build directory.
option(AUTHCORD_BUILD_TESTS "Build the SDK tests" ON)
if(AUTHCORD_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted_login_test.cpp")
    enable_testing()
    add_executable(authcord_hosted_login_test tests/hosted_login_test.cpp)
    add_test(NAME hosted_login COMMAND authcord_hosted_login_test)
    set_tests_properties(hosted_login PROPERTIES TIMEOUT 120)
    list(APPEND _authcord_targets authcord_hosted_login_test)
endif()

foreach(_target ${_authcord_targets})
    target_include_directories(${_target} PRIVATE include)
    target_link_libraries(${_target} PRIVATE ${_authcord_common_libs})
endforeach()
