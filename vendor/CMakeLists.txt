# Private C11 third-party source ownership for the canonical CNet build.
# One renamed Monocypher namespace and one Reed/GF256 target per build.
# Never install or export these source-private libraries as Salts:: providers.
# Monocypher is an INDEPENDENT CMake library under vendor/monocypher.
# Keep its original CNet-private namespace for ABI/wire parity; do not fold
# it into Salts::Crypto or rename its algorithm implementations.
add_subdirectory(monocypher)

# Reed-Solomon/GF(256) is an independent FEC CMake library,
# NOT a cryptographic provider or a Salts::Crypto implementation.
add_subdirectory(reed)

# Keep the existing third-party license install layout without
# making CNet a second owner of the vendored source or license inputs.
install(FILES reed/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/reed)
install(FILES monocypher/UPSTREAM.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/SaltsCore/monocypher)
