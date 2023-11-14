add_custom_target(examples
    ALL
    ninja -C ${CMAKE_CURRENT_SOURCE_DIR}
    # TODO: Add BYPRODUCTS?
)

