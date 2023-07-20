set(SPECULOS_DIR "$ENV{SPECULOS_DIR}" CACHE INTERNAL "Copied from environment variable")
set(BOLOS_SDK_DIR "$ENV{BOLOS_SDK_DIR}" CACHE INTERNAL "Copied from environment variable")


add_library(ux
        glyphs.c
        ux.c
        ux_display.c)

if (NOT NATIVE)
  target_include_directories (ux PUBLIC ../risc-v/)
else()
  target_include_directories (ux PUBLIC ../native/ ${SPECULOS_DIR}/src/ ${SPECULOS_DIR}/src/bolos/)
endif()