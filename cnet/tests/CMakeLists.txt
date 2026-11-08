add_executable(cnet_tls_server_ticket_peer tls_server_tickets.c)
file(GLOB _cnet_dtls_test_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_native_*.c")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_cnet_dtls_test_sources})
add_executable(cnet_dtls_native_peer ${_cnet_dtls_test_sources})
target_link_libraries(cnet_dtls_native_peer PRIVATE Salts::CNet Salts::Platform)
set_target_properties(cnet_dtls_native_peer PROPERTIES FOLDER "CNet/tests")
file(GLOB _cnet_dtls_cpp_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/dtls_header_*.cpp")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" PREFIX "tests" FILES ${_cnet_dtls_cpp_sources})
add_executable(cnet_dtls_header_cpp ${_cnet_dtls_cpp_sources})
target_compile_features(cnet_dtls_header_cpp PRIVATE cxx_std_17)
target_link_libraries(cnet_dtls_header_cpp PRIVATE Salts::CNet Salts::TinyTest)
set_target_properties(cnet_dtls_header_cpp PROPERTIES FOLDER "CNet/tests")
add_test(NAME saltscore.cnet_dtls_cpp17 COMMAND cnet_dtls_header_cpp)
target_link_libraries(cnet_tls_server_ticket_peer PRIVATE Salts::CNet Salts::TinyTest)
set_target_properties(cnet_tls_server_ticket_peer PROPERTIES FOLDER "CNet/tests")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  find_program(SALTS_CNET_TICKET_GO go REQUIRED)
  add_test(NAME saltscore.cnet_dtls_native
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -failfast -v -timeout=90s -run "^TestDTLSNative"
      -args -dtls-native "$<TARGET_FILE:cnet_dtls_native_peer>")
  set_tests_properties(saltscore.cnet_dtls_native PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
  add_test(NAME saltscore.cnet_tls_server_tickets
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=90s -run "^TestServerTickets$"
      -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_tls_server_tickets PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 120)
  add_test(NAME saltscore.cnet_pkix_name_constraints
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestNameConstraints$" -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_pkix_name_constraints PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tickets"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
  add_test(NAME saltscore.cnet_tlcp_anchor_constraints
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestTLCPAnchorConstraints$" -args -native "$<TARGET_FILE:saltscore_cnet_tls_ca_san_test>")
  set_tests_properties(saltscore.cnet_tlcp_anchor_constraints PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/independent/tlcp"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
  add_test(NAME saltscore.cnet_shangmi_server_tickets
    COMMAND "${SALTS_CNET_TICKET_GO}" test -mod=readonly -count=1 -timeout=60s
      -run "^TestShangMiServerTickets$" -args -native "$<TARGET_FILE:cnet_tls_server_ticket_peer>")
  set_tests_properties(saltscore.cnet_shangmi_server_tickets PROPERTIES
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/tests/independent/shangmi"
    ENVIRONMENT "CGO_ENABLED=0;GOWORK=off" TIMEOUT 90)
endif()
