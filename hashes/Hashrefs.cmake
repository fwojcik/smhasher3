#message(STATUS "Generating hash family list from sources")

# In theory this file(REMOVE) shouldn't be necessary, but it is. This
# avoids configure_file() below erroneously thinking we don't need to
# regenerate it when we know for a fact we do, since dependencies are
# really being handled in the main CMakeLists.txt file and we know
# that this code is only ever called at all when the output file
# definitely needs to be regenerated.
file(REMOVE ${DST})

include(${SRCDIR}/hashes/Hashsrc.cmake)

foreach(hashsrc ${HASH_SRC_FILES})
  file(STRINGS ${SRCDIR}/${hashsrc} hashfam REGEX "^[ \t\r\n]*REGISTER_FAMILY\\([^,]+[,)]")
  if("${hashfam}" STREQUAL "")
    message(WARNING "Could not parse out a REGISTER_FAMILY() call in ${hashsrc}!\nHashes in that file will not be usable!")
  else()
    string(REGEX REPLACE "^[ \t\r\n]*REGISTER_FAMILY\\(" "USE_FAMILY(" hashfam ${hashfam})
    string(REGEX REPLACE "[,)].*" ");" hashfam ${hashfam})
    #message(STATUS "File ${hashsrc} found ${hashfam}")
    set(HASH_USE_FAMILY_CALLS "${HASH_USE_FAMILY_CALLS}    ${hashfam}\n")
  endif()
endforeach()

configure_file(${SRC} ${DST} @ONLY)
