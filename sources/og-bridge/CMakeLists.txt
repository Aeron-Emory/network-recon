cmake_minimum_required(VERSION 3.20)
set(PICO_BOARD freewili_og CACHE STRING "Board" FORCE)
set(FWOG_BSP "" CACHE PATH "Pinned wiliOGbsp checkout; see docs/BUILDING.md")
if(NOT EXISTS "${FWOG_BSP}/bsp/CMakeLists.txt")
    message(FATAL_ERROR "Set FWOG_BSP to the pinned wiliOGbsp checkout")
endif()
list(APPEND PICO_BOARD_HEADER_DIRS "${FWOG_BSP}/bsp/boards")
set(PICO_STDIO_UART 0 CACHE BOOL "UART0 is the inter-CPU link" FORCE)
if(NOT PICO_SDK_PATH)
    set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
endif()
if(NOT EXISTS "${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
    message(FATAL_ERROR "Set PICO_SDK_PATH to the pinned Pico SDK checkout")
endif()
include("${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
project(bnbridge C CXX ASM)
set(CMAKE_C_STANDARD 11)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
pico_sdk_init()
set(FWOG_GIT_DESCRIBE "bnbridge-004")
set(FWOG_GIT_COMMIT_TS 0)
find_program(PICOTOOL_EXECUTABLE NAMES picotool REQUIRED)
add_executable(picotool IMPORTED GLOBAL)
set_target_properties(picotool PROPERTIES IMPORTED_LOCATION "${PICOTOOL_EXECUTABLE}")
add_subdirectory("${FWOG_BSP}/bsp" bsp)
add_subdirectory("${FWOG_BSP}/apps/bl" bl)

add_executable(bnbridge_display display/main.c display/radio_console.c)
target_include_directories(bnbridge_display PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(bnbridge_display fwog_display_bsp)
target_compile_definitions(bnbridge_display PRIVATE PICO_STDIO_USB_ENABLE_IRQ_BACKGROUND_TASK=0
    CFG_TUD_CDC_TX_BUFSIZE=4096 CFG_TUD_CDC_RX_BUFSIZE=1024)
target_compile_options(bnbridge_display PRIVATE -Wall -Wextra)
fwog_display_app(bnbridge_display VERSION 004
    DESCRIPTION "Bottlenose bridge power control and independent UART loss counters")

add_executable(bnbridge_main main/main.c main/radio_rx.c)
target_include_directories(bnbridge_main PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(bnbridge_main fwog_main_bsp)
# Keep the SDK USB descriptors and 1200-baud recovery. Service TinyUSB in
# this main loop so its task cannot race direct CDC FIFO accesses.
target_compile_definitions(bnbridge_main PRIVATE
    PICO_STDIO_USB_ENABLE_IRQ_BACKGROUND_TASK=0
    PICO_STDIO_USB_DEFAULT_CRLF=0
    CFG_TUD_CDC_TX_BUFSIZE=4096 CFG_TUD_CDC_RX_BUFSIZE=1024)
target_compile_options(bnbridge_main PRIVATE -Wall -Wextra)
fwog_embed_display_image(bnbridge_main)
fwog_main_app(bnbridge_main VERSION 004
    DESCRIPTION "Bottlenose raw USB bridge plus independent dual CC1101 receive controls")
