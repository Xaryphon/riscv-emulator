set(RV_CC riscv64-elf-gcc CACHE STRING "")
set(RV_CFLAGS "-Wall -Werror" CACHE STRING "")

if(RV_XLEN EQUAL 32)
    set(RV_MABI ilp32)
elseif(RV_XLEN EQUAL 64)
    set(RV_MABI lp64)
else()
    message(FATAL_ERROR "Invalid XLEN")
endif()

set(RV_MARCH rv${RV_XLEN}i)

# NOTE: We have to use a custom build.ninja to be able to have our custom
#       commands listed in a compile_commands.json file in a reasonable way

# FIXME: Out of tree build
configure_file(
    build.ninja.in
    ${CMAKE_CURRENT_SOURCE_DIR}/build.ninja
    @ONLY
)

if(CMAKE_EXPORT_COMPILE_COMMANDS)
    execute_process(
        COMMAND ninja -t compdb
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json
    )
endif()

add_custom_target(examples
    ALL
    ninja
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    # TODO: Add BYPRODUCTS?
)

