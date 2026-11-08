file(GLOB _dtls_native_tests CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_native_*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_dtls_native_tests})
add_executable(cnet_sctp_dtls_native_peer ${_dtls_native_tests})
target_link_libraries(cnet_sctp_dtls_native_peer PRIVATE Salts::SCTPDTLS Salts::Platform)
set_target_properties(cnet_sctp_dtls_native_peer PROPERTIES FOLDER "SCTP/tests")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_SCTP_DTLS_GO go REQUIRED)
  add_test(NAME saltscore.sctp_dtls_native
    COMMAND "${SALTS_SCTP_DTLS_GO}" test -mod=readonly -count=1 -failfast -v -timeout=120s
      -args -native "$<TARGET_FILE:cnet_sctp_dtls_native_peer>")
  set_tests_properties(saltscore.sctp_dtls_native PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/secure"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 150)
endif()
