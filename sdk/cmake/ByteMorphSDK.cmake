# ByteMorph CMake SDK Integration (v0.12.0)

function(bytemorph_protect_target TARGET_NAME)
    cmake_parse_arguments(
        BM
        "ALL_ELIGIBLE;ENCRYPT_BYTECODE"
        "PROFILE;OUTPUT;REPORT;SEED"
        "FUNCTIONS"
        ${ARGN}
    )

    if(NOT BM_PROFILE)
        set(BM_PROFILE "balanced")
    endif()

    if(NOT BM_OUTPUT)
        set(BM_OUTPUT "$<TARGET_FILE_DIR:${TARGET_NAME}>/$<TARGET_FILE_BASE_NAME:${TARGET_NAME}>_protected$<TARGET_FILE_SUFFIX:${TARGET_NAME}>")
    endif()

    if(TARGET bytemorph)
        set(_bm_cli $<TARGET_FILE:bytemorph>)
    elseif(DEFINED BYTEMORPH_CLI_EXECUTABLE)
        set(_bm_cli "${BYTEMORPH_CLI_EXECUTABLE}")
    else()
        find_program(_bm_cli bytemorph)
    endif()

    if(NOT _bm_cli)
        message(WARNING "ByteMorph CLI not found; skipping post-build protection for ${TARGET_NAME}")
        return()
    endif()

    set(_bm_args
        protect
        "$<TARGET_FILE:${TARGET_NAME}>"
        "${BM_OUTPUT}"
        --profile "${BM_PROFILE}"
    )

    if(BM_ALL_ELIGIBLE)
        list(APPEND _bm_args --functions all-eligible)
    elseif(BM_FUNCTIONS)
        foreach(_fn IN LISTS BM_FUNCTIONS)
            list(APPEND _bm_args --function "${_fn}")
        endforeach()
    else()
        list(APPEND _bm_args --auto-select)
    endif()

    if(BM_ENCRYPT_BYTECODE)
        list(APPEND _bm_args --encrypt-bytecode)
    endif()

    if(BM_SEED)
        list(APPEND _bm_args --seed "${BM_SEED}")
    endif()

    add_custom_command(
        TARGET ${TARGET_NAME}
        POST_BUILD
        COMMAND ${_bm_cli} ${_bm_args}
        COMMENT "ByteMorph (${BM_PROFILE}): protecting ${TARGET_NAME} -> ${BM_OUTPUT}"
        VERBATIM
    )

    if(BM_REPORT)
        add_custom_command(
            TARGET ${TARGET_NAME}
            POST_BUILD
            COMMAND ${_bm_cli} report "${BM_OUTPUT}" --format json > "${BM_REPORT}"
            COMMENT "ByteMorph: writing protection report -> ${BM_REPORT}"
            VERBATIM
        )
    endif()
endfunction()
