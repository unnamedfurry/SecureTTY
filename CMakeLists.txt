cmake_minimum_required(VERSION 3.20)
project(SecureTTY C)

set(CMAKE_C_STANDARD 23)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(RAYLIB raylib)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(MYSQL mysqlclient)

if (RAYLIB_FOUND)
    link_directories(${RAYLIB_LIBRARY_DIRS})
else()
    find_library(RAYLIB_LIBRARY raylib REQUIRED)
    set(RAYLIB_LIBRARIES ${RAYLIB_LIBRARY})
endif()

if (MYSQL_FOUND)
    link_directories(${MYSQL_LIBRARY_DIRS})
else()
    find_library(MYSQL_LIBRARY NAMES mysqlclient mariadb REQUIRED)
    find_path(MYSQL_INCLUDE_DIR NAMES mysql.h REQUIRED)
    set(MYSQL_LIBRARIES ${MYSQL_LIBRARY})
    set(MYSQL_INCLUDE_DIRS ${MYSQL_INCLUDE_DIR})
endif()

# Compiling binaries
add_executable(client client/client.c
                      client/text-util.c
                      client/GuiFileSelector.c
                      client/math.c
                      client/network-util.c
                      client/shared-variables.h
                      client/config-util.c
                      client/shared-variables.c
                      client/cryptography.c)
add_executable(server server/server.c
                      server/accept-client.c
                      server/cryptography.c
                      server/client-manager.c
                      server/shared-variables.h
                      server/text-util.c
                      server/client-actions.c
                      server/network-util.c
                      server/shared-variables.c)
# Linking libraries to binaries AUTOMATICALLY
target_link_libraries(client PRIVATE ${RAYLIB_LIBRARIES} GL m pthread dl rt X11 Xrandr Xinerama Xi Xcursor OpenSSL::SSL OpenSSL::Crypto ${SODIUM_LIBRARIES})
target_link_libraries(server PRIVATE m pthread OpenSSL::SSL OpenSSL::Crypto ${MYSQL_LIBRARIES} ${SODIUM_LIBRARIES})
# Linking libraries to binaries MANUALLY
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/build_include ${RAYLIB_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_include_directories(server PRIVATE ${MYSQL_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
# Sort binaries by folders
set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/client")
set_target_properties(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/server")