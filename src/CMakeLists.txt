include(CheckIncludeFileCXX)

add_subdirectory ( codecs )
add_subdirectory ( daqs )
add_subdirectory ( inspectors )
add_subdirectory ( ips_options )
add_subdirectory ( loggers )
add_subdirectory ( search_engines )
add_subdirectory ( so_rules )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )
find_path ( ENABLE_APPID_THIRD_PARTY tp_appid_module_api.h
    HINTS ${SNORT3_INCLUDE_DIRS}
    PATH_SUFFIXES "network_inspectors/appid" )

if ( ENABLE_APPID_THIRD_PARTY )
  add_subdirectory ( tp_appid )
endif()
