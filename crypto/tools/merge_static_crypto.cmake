# Merge the already compiled patched GmSSL archive with all locally built
# Crypto/TLS/CipherBIO/SHA256/Ed448 objects into ONE deployable static archive.
# The component libraries are staging inputs, never installed or propagated.
cmake_minimum_required(VERSION 3.21)
foreach(_arg IN ITEMS ARCHIVE GMSSL_ARCHIVE ARCHIVER)
  if(NOT DEFINED ${_arg} OR "${${_arg}}" STREQUAL "")
    message(FATAL_ERROR "Crypto static merge missing ${_arg}")
  endif()
endforeach()
if(NOT EXISTS "${ARCHIVE}" OR NOT EXISTS "${GMSSL_ARCHIVE}")
  message(FATAL_ERROR "Crypto static merge requires both input archives")
endif()
if(NOT WIN32 AND NOT APPLE AND (NOT DEFINED RANLIB OR RANLIB STREQUAL ""))
  message(FATAL_ERROR "Crypto static merge requires RANLIB")
endif()
set(_own "${ARCHIVE}.objects")
file(RENAME "${ARCHIVE}" "${_own}")
if(WIN32)
  execute_process(COMMAND "${ARCHIVER}" "/NOLOGO" "/OUT:${ARCHIVE}"
    "${_own}" "${GMSSL_ARCHIVE}"
    COMMAND_ERROR_IS_FATAL ANY)
elseif(APPLE)
  execute_process(COMMAND "/usr/bin/libtool" -static -o "${ARCHIVE}"
    "${_own}" "${GMSSL_ARCHIVE}"
    COMMAND_ERROR_IS_FATAL ANY)
else()
  set(_mri "${ARCHIVE}.mri")
  file(WRITE "${_mri}" "CREATE \"${ARCHIVE}\"\nADDLIB \"${_own}\"\nADDLIB \"${GMSSL_ARCHIVE}\"\nSAVE\nEND\n")
  execute_process(COMMAND "${ARCHIVER}" -M INPUT_FILE "${_mri}"
    COMMAND_ERROR_IS_FATAL ANY)
  file(REMOVE "${_mri}")
  execute_process(COMMAND "${RANLIB}" "${ARCHIVE}"
    COMMAND_ERROR_IS_FATAL ANY)
endif()
if(NOT EXISTS "${ARCHIVE}")
  message(FATAL_ERROR "Crypto static archive merge did not produce ${ARCHIVE}")
endif()
file(REMOVE "${_own}")
