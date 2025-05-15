cmake_minimum_required ( VERSION 3.5 )
project ( alert_lua )

install (
    FILES alert.lua
    DESTINATION "${LOGGER_INSTALL_PATH}"
)
