function(findVariant prefix)
  set(impl        "${prefix}_IMPL")
  set(implfile    "${prefix}_IMPLFILE")
  set(isfallback  "${prefix}_FALLBACK")
  set(variantsvar "${prefix}_VARIANTS")
  mark_as_advanced(${implfile} ${isfallback})

  #message(STATUS "Given: ${${variantsvar}}")

  # If the result of findVariant is cached, just use that. See below
  # for why the implementation itself cannot be cached and has to be
  # reread from the file.
  if((DEFINED ${isfallback}) AND (DEFINED ${implfile}) AND (EXISTS ${${implfile}}))
    file(READ "${${implfile}}" IMPL)
    string(REGEX REPLACE "\n$" "" IMPL "${IMPL}")
    set(${impl} ${IMPL} PARENT_SCOPE)
    list(GET ${variantsvar} 0 desc)
    if(${isfallback})
      message(STATUS "  ${desc} not found, using fallback")
    else()
      message(STATUS "  ${desc} found")
    endif()
    return()
  endif()

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

  # Expand the preamble
  string(REGEX REPLACE "'" ";" PREAMBLE ${PREAMBLE})
  string(CONFIGURE "@WINLIKE_IMPL@\n${PREAMBLE}" PREAMBLE @ONLY)

  # The file that is used to verify each variant's suitability
  set(SRCFILENAME "${DETECT_DIR}/${FILEPREFIX}_test.cpp")
  list(APPEND ${VARIANT_FILELISTVAR} "${SRCFILENAME}")

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
    list(APPEND ${VARIANT_FILELISTVAR} "${FN}")
    #message(STATUS "Trying ${FN}")
    #message(STATUS "${PREAMBLE}${ATTEMPT}")

    # Write out the variant and see if it works.
    file(WRITE ${CMAKE_BINARY_DIR}/curvariant.h
      "${PREAMBLE}${ATTEMPT}")
    try_compile(WORKED ${CMAKE_BINARY_DIR}
      SOURCES ${SRCFILENAME}
      CMAKE_FLAGS -DINCLUDE_DIRECTORIES:PATH=${CMAKE_BINARY_DIR}
      OUTPUT_VARIABLE dump
    )

    # Record output from compilation attempts
    list(APPEND COMPILER_OUTPUTS ${dump})
    #message(STATUS "Got result ${dump} for ${ATTEMPT}")

    if(WORKED)
      set(IMPL ${ATTEMPT})
      break()
    endif()
  endforeach()

  # If detection fails, then delete whatever happened to be the last
  # variant that was tried, so it doesn't confuse the issue.
  if(NOT WORKED)
    file(REMOVE ${CMAKE_BINARY_DIR}/curvariant.h)
  endif()

  if(${isfallback})
    if(NOT WORKED)
      message(STATUS "Compiler outputs for compilation attempts:")
      message(STATUS "${COMPILER_OUTPUTS}")
      if(NOT EXISTS "${FN}")
        message(FATAL_ERROR "\
Fallback not possible for ${FILEPREFIX} (${desc})! Cannot continue.\n\
The compiler outputs above may give a clue to the root cause.\n")
      else()
        message(FATAL_ERROR "\
Fallback variant for ${FILEPREFIX} (${desc}) failed! Cannot continue.\n\
The compiler outputs above may give a clue to the root cause.\n")
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

  # Cache the chosen variant's file and fallback status. We can't
  # cache the actual implementation because C++ often uses lines that
  # end in semi-colons (;) and that interfere's with CMake's string
  # handling... :-(
  set(${implfile} "${FN}" CACHE STRING "Implementation of ${desc}" FORCE)
  set(${isfallback} ${${isfallback}} CACHE BOOL "Implementation of ${desc} is fallback" FORCE)

  # Mark the cachable variables that this changes
  list(APPEND ${VARIANT_VARLISTVAR} "${implfile}" "${isfallback}")

  # "Return" the impl to the parent context, as well as the lists of
  # cached files and variables
  set(${impl} ${IMPL} PARENT_SCOPE)
  set(${VARIANT_FILELISTVAR} ${${VARIANT_FILELISTVAR}} PARENT_SCOPE)
  set(${VARIANT_VARLISTVAR} ${${VARIANT_VARLISTVAR}} PARENT_SCOPE)

endfunction()




# Function to associate a list of files with a list of variables, such
# that if *any* file in the given list changes, then *all* of the
# variables in the given list are cleared and removed from CMake's
# cache as well as current memory.
#
# This apparently has to happen manually, since there's NO OTHER WAY
# of clearing these cached variables iff the files post-date the CMake
# cache... :-{
function(setCachedVarsDepend PREFIX varListVar fileListVar)
  # If the cached data didn't change, then don't do anything except
  # for telling CMake AGAIN what files the config depends on, because
  # if it reconfigures for some reason other than these files then it
  # will forget about them  :-{
  if((DEFINED ${PREFIX}hashList) AND (DEFINED ${PREFIX}fileList) AND
     (DEFINED ${PREFIX}varList))
    #message(STATUS "Making config depend on: ${${PREFIX}fileList}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${${PREFIX}fileList})
    return()
  endif()

  # Mark cmake configuration as depending on the files, so that the
  # needed code will even run when they change (as CMake will just
  # skip reconfiguing unless it detects that it needs to).
  #message(STATUS "Making config depend on: ${${fileListVar}}")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${${fileListVar}})

  # Record all of the hashes of all given files
  unset(fileHashes)
  foreach(file ${${fileListVar}} "${DETECT_DIR}/functions.cmake")
    file(SHA256 ${file} filehash)
    list(APPEND fileHashes ${filehash})
  endforeach()

  # Cache the list of variables, the list of files and their hashes
  # under the given prefix
  set("${PREFIX}varList"  "${${varListVar}}"  CACHE STRING "List of ${PREFIX} variables" FORCE)
  set("${PREFIX}fileList" "${${fileListVar}}" CACHE STRING "List of files for ${PREFIX} variables" FORCE)
  set("${PREFIX}hashList" "${fileHashes}"     CACHE STRING "List of hashes of ${PREFIX} files" FORCE)
  mark_as_advanced(FORCE "${PREFIX}varList" "${PREFIX}fileList" "${PREFIX}hashList")

endfunction()

# Function that actually does unset all the given variables if any of
# the associated files changed.
#
# Note that due to the way CMake's cache works, this function should
# actually be called *before* setCachedVarsDepend() with a given prefix.
function(checkCachedVarsDepend PREFIX desc)

  if((NOT DEFINED ${PREFIX}hashList) OR (NOT DEFINED ${PREFIX}fileList) OR
     (NOT DEFINED ${PREFIX}varList))
    message(STATUS "Probing ${desc}")
    return()
  endif()

  unset(fileHashes)
  foreach(file ${${PREFIX}fileList} "${DETECT_DIR}/functions.cmake")
    if(NOT EXISTS ${file})
      #message(STATUS "File not found: ${file}")
      set(fileHashes "thisstringnevermatches")
      break()
    endif()
    file(SHA256 ${file} filehash)
    list(APPEND fileHashes ${filehash})
  endforeach()

  if(${PREFIX}hashList STREQUAL fileHashes)
    message(STATUS "Using cached ${desc}")
    return()
  endif()

  message(STATUS "Clearing ${desc} cache, reprobing")
  foreach(varname ${${PREFIX}varList} ${PREFIX}hashList ${PREFIX}fileList ${PREFIX}varList)
    #message(STATUS "Clearing ${varname}")
    unset(${varname} CACHE)
    unset(${varname})
  endforeach()

endfunction()
