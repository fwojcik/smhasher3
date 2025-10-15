if(GIT_EXECUTABLE)
  get_filename_component(SRC_DIR ${SRC} DIRECTORY)

  # Figure out which branch we are on
  execute_process(
    COMMAND ${GIT_EXECUTABLE} branch --show-current
    WORKING_DIRECTORY ${SRC_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    RESULT_VARIABLE GIT_BRANCH_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  if(NOT GIT_BRANCH_ERROR_CODE)
    # Generate a git-describe version string.
    # Have to do this in two parts; thanks, git!
    if (GIT_BRANCH)
      execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --all --always
		--exclude "dev" --exclude "*/dev"
		--exclude "main" --exclude "*/main"
		--exclude "${GIT_BRANCH}" --exclude "*/${GIT_BRANCH}"
		HEAD
        WORKING_DIRECTORY ${SRC_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE_VERSION_A
        RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    else()
      execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --all --always HEAD
        WORKING_DIRECTORY ${SRC_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE_VERSION_A
        RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    endif()

    execute_process(
      COMMAND ${GIT_EXECUTABLE} describe --dirty --always
      WORKING_DIRECTORY ${SRC_DIR}
      OUTPUT_VARIABLE GIT_DESCRIBE_VERSION_B
      RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # I can't believe there's no better way to do this...
    set(OLD_TZ $ENV{TZ})
    set(ENV{TZ} "UTC0")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} show --format=%cd --date=format-local:%Y%m%d -s HEAD
      WORKING_DIRECTORY ${SRC_DIR}
      OUTPUT_VARIABLE GIT_DESCRIBE_DATE
      RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(ENV{TZ} ${OLD_TZ})

    # A ~ "heads/master-506-ge042461"   B ~ "e042461-dirty"
    if(GIT_DESCRIBE_VERSION_A AND GIT_DESCRIBE_VERSION_B)
      string(REGEX REPLACE "^[^/]*/" "" GIT_DESCRIBE_VERSION_A ${GIT_DESCRIBE_VERSION_A})
      string(REGEX REPLACE "-g[0-9a-fA-F]+" "" GIT_DESCRIBE_VERSION_A ${GIT_DESCRIBE_VERSION_A})
      string(CONCAT SMHASHER3_GIT_VERSION ${GIT_DESCRIBE_DATE} "-" ${GIT_DESCRIBE_VERSION_A} "-" ${GIT_DESCRIBE_VERSION_B})
    endif()
    if((NOT GIT_DESCRIBE_VERSION_A) AND GIT_DESCRIBE_VERSION_B)
      string(CONCAT SMHASHER3_GIT_VERSION ${GIT_DESCRIBE_DATE} "-unknown-0-" ${GIT_DESCRIBE_VERSION_B})
    endif()

  endif()
endif()

if(NOT DEFINED SMHASHER3_GIT_VERSION)
  set(SMHASHER3_GIT_VERSION "master-unknown")
endif()

configure_file(${SRC} ${DST} @ONLY)
