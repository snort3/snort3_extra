# Install script for directory: /home/armin/snort3_extra/src/codecs

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/opt/snort3")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/armin/snort3_extra/build/src/codecs/cd_eapol/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_linux_sll/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_null/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_pflog/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_pbb/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_ppp/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_slip/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_token_ring/cmake_install.cmake")
  include("/home/armin/snort3_extra/build/src/codecs/cd_wlan/cmake_install.cmake")

endif()

