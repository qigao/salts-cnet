cmake_minimum_required(VERSION 3.20)
# CTest PASS_REGULAR_EXPRESSION can turn a nonzero test exit into success.
# Require the original selected TinyTest case, exit zero, and exactly one pass.
if(NOT DEFINED CNET_NUMERIC_HOST_COMMAND OR CNET_NUMERIC_HOST_COMMAND STREQUAL "")
  message(FATAL_ERROR "CNET_NUMERIC_HOST_COMMAND must identify the original Owner test")
endif()
list(GET CNET_NUMERIC_HOST_COMMAND 0 _exe)
if(NOT EXISTS "${_exe}")
  message(FATAL_ERROR "Original Owner executable not found: ${_exe}")
endif()
set(_case "owns the resolve to TCP connect state transition")
execute_process(
  COMMAND ${CNET_NUMERIC_HOST_COMMAND} --filter "${_case}"
  RESULT_VARIABLE _status OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr TIMEOUT 12)
set(_output "${_stdout}\n${_stderr}")
if(NOT "${_status}" STREQUAL "0")
  message(FATAL_ERROR "Original numeric-host Owner failed with exit=${_status}\n${_output}")
endif()
string(FIND "${_output}" "${_case}" _name_index)
if(_name_index LESS 0)
  message(FATAL_ERROR "Original numeric-host TinyTest case name missing\n${_output}")
endif()
# The TinyTest summary must confirm one selected/finished case. A printed
# case name alone is not evidence that the filtered test actually ran.
if(NOT _output MATCHES "(^|[^0-9])1 passed, 0 failed, 0 skipped, [0-9]+ filtered, 0 todo, [0-9]+ assertions\\.")
  message(FATAL_ERROR "Expected exactly one selected and passed original Owner test\n${_output}")
endif()
message(STATUS "CNET_NUMERIC_HOST_ONE_CASE_PASS: 1 pass, 0 failed/skipped/todo, process exit 0")
