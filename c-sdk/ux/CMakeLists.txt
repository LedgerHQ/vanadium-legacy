set(SPECULOS_DIR "$ENV{SPECULOS_DIR}" CACHE INTERNAL "Copied from environment variable")
set(BOLOS_SDK_DIR "$ENV{BOLOS_SDK_DIR}" CACHE INTERNAL "Copied from environment variable")


add_library(ux
        glyphs.c
        ux.c
        ux_display.c)

if (NOT NATIVE)
  target_include_directories (ux PUBLIC ../risc-v/)
else()
  target_include_directories (ux PUBLIC ../native/ PUBLIC native/ ${BOLOS_SDK_DIR}/include ${BOLOS_SDK_DIR}/lib_cxng/include ${BOLOS_SDK_DIR}/target/nanox/include/)
endif()