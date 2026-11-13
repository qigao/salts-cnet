# One wire codec, opaque SCTP session, and the explicit CNet/DTLS bridge.
cmake_add_source(wire_sources DIRS src PATTERNS sctp_wire.c sctp_wire_internal.h)
add_library(cnet_sctp_wire STATIC ${wire_sources})
cmake_config_target(cnet_sctp_wire ALIAS Salts::SCTPWire EXPORT_NAME SCTPWire FOLDER "sctp")
cmake_add_source(session_sources DIRS src
  EXCLUDES src/sctp_wire.c src/sctp_dtls_bridge.c)
add_library(cnet_sctp_session STATIC ${session_sources})
cmake_config_target(cnet_sctp_session ALIAS Salts::SCTP EXPORT_NAME SCTP FOLDER "sctp")
target_link_libraries(cnet_sctp_session PUBLIC cnet_sctp_wire)
file(GLOB dtls_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/sctp_dtls_*.c")
add_library(cnet_sctp_dtls STATIC ${dtls_sources})
cmake_config_target(cnet_sctp_dtls ALIAS Salts::SCTPDTLS EXPORT_NAME SCTPDTLS FOLDER "sctp")
target_link_libraries(cnet_sctp_dtls PUBLIC Salts::SCTP Salts::CNet)
cmake_add_source(module_headers RECURSE DIRS include PATTERNS "*.h")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}"
  FILES ${wire_sources} ${session_sources} ${dtls_sources} ${module_headers})
foreach(target IN ITEMS cnet_sctp_wire cnet_sctp_session cnet_sctp_dtls)
  target_sources(${target} PRIVATE ${module_headers})
  target_include_directories(${target}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE src)
  set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
install(TARGETS cnet_sctp_wire cnet_sctp_session cnet_sctp_dtls
  EXPORT SaltsCNetTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
