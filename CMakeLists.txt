# Optional build system. `install.sh` does NOT use this -- it calls g++/gcc
# directly (see its "5. Build" section) so a fresh server never needs cmake
# installed just to build Loguard. This file exists for people who prefer
# `cmake && make`, IDE integration, or packaging (deb/rpm) tooling.
#
# Usage:
#   mkdir -p build && cd build
#   cmake ..
#   make -j
#   sudo make install

cmake_minimum_required(VERSION 3.16)
project(loguard LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_RELEASE "-O2")

add_executable(loguard
    src/main.cpp
    src/util.cpp
    src/config.cpp
    src/telegram.cpp
    src/queue.cpp
    src/pam.cpp
    src/integrity.cpp
    src/session.cpp
    src/session_queue.cpp
    src/geoip.cpp
    src/risk_engine.cpp
    src/pattern_matcher.cpp
    src/process_monitor.cpp
)

add_executable(loguard-notify
    src/pam_hook.c
)
set_target_properties(loguard-notify PROPERTIES LINKER_LANGUAGE C)

install(TARGETS loguard loguard-notify
    RUNTIME DESTINATION /opt/loguard/bin
)
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink /opt/loguard/bin/loguard /usr/local/bin/loguard)")

# Note: this target does NOT create /etc/loguard, /var/lib/loguard,
# /var/log/loguard, install systemd units, or run the interactive Telegram
# setup wizard -- that orchestration lives in install.sh. Run install.sh
# (or replicate its "6. Install files" / "7. Telegram setup" steps by hand)
# after `make install` if you build this way.