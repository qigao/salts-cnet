# Run the original, non-reflected C11 unit and Unicode 17 data-oracle tests
# against only the Core-owned native targets. No old Salts test macros/shims.
function(saltscore_native_case name source owner)
  if(NOT TARGET Salts::TinyTest OR NOT TARGET "${owner}")
    message(FATAL_ERROR "Missing native module owner for conformance: ${owner}")
  endif()
  add_executable("${name}" "${PROJECT_SOURCE_DIR}/${source}")
  target_compile_features("${name}" PRIVATE c_std_11)
  set_target_properties("${name}" PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries("${name}" PRIVATE "${owner}" Salts::TinyTest)
  add_test(NAME "saltscore.native.${name}" COMMAND "${name}")
  set_tests_properties("saltscore.native.${name}" PROPERTIES TIMEOUT 300)
endfunction()

# BUILD_TESTING=ON always provides TinyTest; its original regression suites
# must be registered just like all other actual native tests.
foreach(_name IN ITEMS regression_fixes regression_runtime equality_test
    result_x_macro_test c11_generic_test)
  saltscore_native_case("tinytest_${_name}"
    "tinytest/test/${_name}.c" Salts::TinyTest)
endforeach()

if(SALTSCORE_BUILD_CSERDE)
  foreach(_name IN ITEMS cserde_token_test cserde_reader_test cserde_writer_test)
    saltscore_native_case("${_name}"
      "cserde/tests/${_name}.c" Salts::CSerde)
  endforeach()
  add_library(saltscore_cserde_recording_support STATIC
    "${PROJECT_SOURCE_DIR}/cserde/tests/support/recording.c")
  target_compile_features(saltscore_cserde_recording_support PRIVATE c_std_11)
  target_include_directories(saltscore_cserde_recording_support PUBLIC
    "${PROJECT_SOURCE_DIR}/cserde/tests/support")
  target_link_libraries(saltscore_cserde_recording_support PUBLIC Salts::CSerde)
  saltscore_native_case(cserde_recording_test
    "cserde/tests/cserde_recording_test.c" Salts::CSerde)
  target_link_libraries(cserde_recording_test
    PRIVATE saltscore_cserde_recording_support)
endif()


if(SALTSCORE_BUILD_UNICODE)
  foreach(_name IN ITEMS test_salts_unicode test_salts_unicode_normalize
      test_salts_unicode_casefold test_salts_unicode_combined_abi
      test_salts_unicode_category_conformance
      test_salts_unicode_grapheme test_salts_unicode_grapheme_conformance
      test_salts_unicode_word test_salts_unicode_word_conformance
      test_salts_unicode_line_break_conformance
      test_salts_unicode_bidi test_salts_unicode_bidi_conformance
      test_salts_unicode_emoji test_salts_unicode_emoji_conformance)
    saltscore_native_case("${_name}"
      "unicode/test/${_name}.c" Salts::Unicode)
  endforeach()
  target_compile_definitions(test_salts_unicode_normalize PRIVATE
    "SALTS_NFC_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/NormalizationTest.txt\"")
  target_compile_definitions(test_salts_unicode_casefold PRIVATE
    "SALTS_UNICODE_CASEFOLD_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/CaseFolding.txt\"")
  target_compile_definitions(test_salts_unicode_category_conformance PRIVATE
    "SALTS_UNICODE_CATEGORY_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/UnicodeData.txt\"")
  target_compile_definitions(test_salts_unicode_grapheme_conformance PRIVATE
    "SALTS_UNICODE_GRAPHEME_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/GraphemeBreakTest.txt\"")
  target_compile_definitions(test_salts_unicode_word_conformance PRIVATE
    "SALTS_UNICODE_WORD_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/WordBreakTest.txt\"")
  target_compile_definitions(test_salts_unicode_line_break_conformance PRIVATE
    "SALTS_UNICODE_LINE_BREAK_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/LineBreakTest.txt\"")
  target_compile_definitions(test_salts_unicode_bidi_conformance PRIVATE
    "SALTS_UNICODE_BIDI_PARAGRAPH_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/BidiParagraphTest.txt\"")
  target_compile_definitions(test_salts_unicode_emoji_conformance PRIVATE
    "SALTS_UNICODE_EMOJI_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/emoji-data.txt\"")
endif()

if(SALTSCORE_BUILD_IDNA)
  foreach(_name IN ITEMS test_salts_idna test_salts_idna_conformance)
    saltscore_native_case("${_name}" "idna/test/${_name}.c" Salts::IDNA)
  endforeach()
  target_compile_definitions(test_salts_idna_conformance PRIVATE
    "SALTS_IDNA_TEST_DATA=\"${PROJECT_SOURCE_DIR}/unicode/data/17.0.0/IdnaTestV2.txt\"")
endif()

# C++17 header/layout conformance uses original C++ assertions but no CMeta.
if(SALTSCORE_NATIVE_CPP_CONFORMANCE)
  enable_language(CXX)
  foreach(_pair IN ITEMS
      "CSerde;cserde_header_cpp_test;cserde/tests/cserde_header_cpp_test.cpp"
      "Unicode;test_salts_unicode_header_cpp;unicode/test/test_salts_unicode_header_cpp.cpp")
    list(GET _pair 0 _module)
    list(GET _pair 1 _name)
    list(GET _pair 2 _file)
    if(TARGET "Salts::${_module}")
      add_executable("${_name}" "${PROJECT_SOURCE_DIR}/${_file}")
      target_compile_features("${_name}" PRIVATE cxx_std_17)
      target_link_libraries("${_name}" PRIVATE "Salts::${_module}" Salts::TinyTest)
      add_test(NAME "saltscore.native.${_name}" COMMAND "${_name}")
      set_tests_properties("saltscore.native.${_name}" PROPERTIES TIMEOUT 120)
    endif()
  endforeach()
endif()
