function(findVariant prefix)
  set(impl        "${prefix}_IMPL")
  set(isfallback  "${prefix}_FALLBACK")
  set(variantsvar "${prefix}_VARIANTS")

  # Make a copy of the input variants list
  set(VARIANTS ${${variantsvar}})

  # Get the text description, filename prefix, any prerequisite code,
  # and the number of variants to test. Remove those from our copy of
  # the list.
  list(GET VARIANTS 0 desc)
  list(GET VARIANTS 1 FILEPREFIX)
  list(GET VARIANTS 2 PREAMBLE)
  list(GET VARIANTS 3 COUNT)
  list(REMOVE_AT VARIANTS 0 1 2 3)

  # The file that is used to verify each variant's suitability
  set(FILENAME "${DETECT_DIR}/${FILEPREFIX}_test.cpp")

  # Record if the fallback implementation was chosen
  set(${isfallback} FALSE)

  # Try each variant in order, and stop when a working
  # one is found.
  set(WORKED FALSE)
  foreach(ATTEMPTNUM RANGE 1 ${COUNT})

    # See if we should skip this variant.
    list(LENGTH VARIANTS skipcount)
    if(skipcount GREATER 0)
      list(GET VARIANTS 0 skipnum)
      if(skipnum EQUAL ATTEMPTNUM)
        #message(STATUS "Skipping variant ${ATTEMPTNUM}")
        list(REMOVE_AT VARIANTS 0)
        continue()
      endif()
    endif()

    # If this is the last variant, then it is the fallback.
    if(ATTEMPTNUM EQUAL COUNT)
      set(${isfallback} TRUE)
      set(FN "${DETECT_DIR}/${FILEPREFIX}_fallback.h")
    else()
      set(FN "${DETECT_DIR}/${FILEPREFIX}_variant${ATTEMPTNUM}.h")
    endif()

    # If the variant doesn't exist, then just skip it and warn, unless
    # it's the fallback (last one), in which case don't warn (since
    # this is normal sometimes), and just exit the loop.
    if(NOT EXISTS "${FN}")
      if(${isfallback})
        break()
      else()
        message(STATUS "Warning: variant ${ATTEMPTNUM} not found")
        continue()
      endif()
    endif()

    # Read in the variant, and strip any trailing newline so that the
    # resulting Platform.h file is compact and not full of blank lines.
    file(READ "${FN}" ATTEMPT)
    string(REGEX REPLACE "\n$" "" ATTEMPT "${ATTEMPT}")
    #message(STATUS ${ATTEMPT})

    # Write out the variant and see if it works.
    file(WRITE ${CMAKE_BINARY_DIR}/curvariant.h
      "${PREAMBLE}${ATTEMPT}")
    try_compile(WORKED ${CMAKE_BINARY_DIR}
      SOURCES ${FILENAME}
      CMAKE_FLAGS -DINCLUDE_DIRECTORIES:PATH=${CMAKE_BINARY_DIR}
      OUTPUT_VARIABLE dump
    )
    #message(STATUS "Got result ${dump} for ${ATTEMPT}")
    if(WORKED)
      set(IMPL ${ATTEMPT})
      break()
    endif()
  endforeach()

  if(${isfallback})
    if(NOT WORKED)
      if(NOT EXISTS "${FN}")
        message(FATAL_ERROR
          "Fallback not possible for ${FILEPREFIX} (${desc})! Cannot continue.\n")
      else()
        message(FATAL_ERROR
          "Fallback variant for ${FILEPREFIX} (${desc}) failed! Cannot continue.\n")
      endif()
    else()
      message(STATUS "  ${desc} not found, using fallback")
    endif()
  else()
    # This can theoretically happen if the fallback is configured to
    # be skipped, but nothing does that right now.
    if(NOT WORKED)
      message(FATAL_ERROR
        "No working variant for ${FILEPREFIX} (${desc}) found! Cannot continue.\n")
    else()
      message(STATUS "  ${desc} found")
    endif()
  endif()

  #message(STATUS "setting ${impl} to ${IMPL}")
  set(${impl} ${IMPL} PARENT_SCOPE)
endfunction()
