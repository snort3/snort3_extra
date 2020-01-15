include(CheckIncludeFileCXX)

add_subdirectory ( codecs )
add_subdirectory ( daqs )
add_subdirectory ( inspectors )
add_subdirectory ( ips_options )
add_subdirectory ( loggers )
add_subdirectory ( search_engines )
add_subdirectory ( so_rules )
add_subdirectory ( tp_appid )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )
find_path ( tp_appid_module_api.h
    HINTS ${SNORT3_INCLUDE_DIRS}
    PATH_SUFFIXES "network_inspectors/appid" )

