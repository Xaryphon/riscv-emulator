cmake_minimum_required(VERSION 3.27)

project(RiscVVM C)

set(RV_XLEN 32 CACHE STRING "XLEN")
set_property(CACHE RV_XLEN PROPERTY STRINGS 32 64)
set(RV_EXTENSION_M ON CACHE BOOL "Enable M Extension")

add_subdirectory(examples)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

include(FetchContent)
FetchContent_Declare(
    riscvOpcodes
    GIT_REPOSITORY https://github.com/riscv/riscv-opcodes.git
    GIT_TAG        d5755c9d380f8ab75a98ee9901019ab3f52259dc # 2023-11-09
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)

FetchContent_MakeAvailable(riscvOpcodes)

set(RV_GENERATED_INST_C "${CMAKE_CURRENT_BINARY_DIR}/src/inst.c")
set(RV_GENERATED_INST_H "${CMAKE_CURRENT_BINARY_DIR}/src/inst.h")

add_executable(riscv)
set(decoder_options "-I${RV_XLEN}")
if(RV_EXTENSION_M)
    list(APPEND decoder_options -M)
    target_compile_definitions(riscv
        PRIVATE
            RV_EXTENSION_M=1
    )
endif()

execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/decoder_generator.py" -o "${riscvopcodes_SOURCE_DIR}" -s "${RV_GENERATED_INST_C}" -i "${RV_GENERATED_INST_H}" ${decoder_options}
    COMMAND_ERROR_IS_FATAL ANY
)

target_compile_definitions(riscv
    PRIVATE
        _GNU_SOURCE
        RV_XLEN=${RV_XLEN}
)
target_include_directories(riscv
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_sources(riscv
    PRIVATE
        src/devices/uart/ns16550.c
        src/environment.c
        src/elf_loader.c
        src/exec.c
        src/gdbserver.c
        src/logger.c
        src/main.c
        src/memory_builder.c
        "${RV_GENERATED_INST_C}"
)

