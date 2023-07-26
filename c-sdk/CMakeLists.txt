cmake_minimum_required(VERSION 3.10)

project(RISC-V-apps C ASM)

include(CTest)

option(NATIVE "Build for the host machine instead of RISC-V" OFF)

#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

if (NOT NATIVE)
  if (0)
    message(STATUS "Using clang compiler")
    set(CMAKE_C_COMPILER /usr/bin/clang)
    set(CMAKE_ASM_COMPILER /usr/bin/clang)
    add_compile_options(--target=riscv32 -Oz)
    add_compile_options(-march=rv32im)
    # use gcc linker
    add_link_options(-fuse-ld=/usr/xcc/riscv32-unknown-linux-gnu/bin/riscv32-unknown-linux-gnu-ld --target=riscv32)
    add_link_options(-L/usr/xcc/riscv32-unknown-linux-gnu/lib/gcc/riscv32-unknown-linux-gnu/11.2.0/)
  else ()
    set(CMAKE_C_COMPILER /usr/xcc/riscv32-unknown-linux-gnu/bin/riscv32-unknown-linux-gnu-gcc)
    add_compile_options(-mno-div -mno-fdiv -mstrict-align -Os)
    add_compile_options(-march=rv32g -mabi=ilp32)
    message(STATUS "Using default compiler ${CMAKE_C_COMPILER}")
  endif ()

  add_link_options(-z noseparate-code -static -nostdlib)

  include_directories(/usr/local/riscv32-unknown-linux-gnu/include/ risc-v/)
  link_directories(/usr/local/riscv32-unknown-linux-gnu/lib)
else()
  message(STATUS "Building native binaries")

  if(NOT DEFINED ENV{SPECULOS_DIR})
    message(FATAL_ERROR "Please set SPECULOS_DIR environment variable")
  endif()

  if(NOT DEFINED ENV{BOLOS_SDK_DIR})
    message(FATAL_ERROR "Please set BOLOS_SDK_DIR environment variable")
  endif()

  set(SPECULOS_DIR "$ENV{SPECULOS_DIR}" CACHE INTERNAL "Copied from environment variable")
  set(BOLOS_SDK_DIR "$ENV{BOLOS_SDK_DIR}" CACHE INTERNAL "Copied from environment variable")

  add_compile_definitions(NATIVE)
  # disable sanitizer because the generated libraries can't be used by the Rust app
  #add_compile_options(-fsanitize=address -g -ggdb)
  #add_link_options(-fsanitize=address -g -ggdb)
  link_libraries(crypto)

  enable_testing()
endif()

add_compile_options(-Werror)

# # Make sure to include sdk/ first to prevent ${SPECULOS_DIR}/src/sdk.h
# # being included instead of sdk/sdk.h.

include_directories(BEFORE ./)

# add_subdirectory(sdk)



if (NOT NATIVE)
  add_library(sdk
    crypto.c
    risc-v/div.S
    risc-v/ecall-riscv.c
    risc-v/math.c
    risc-v/start.S
    risc-v/std.c
    sdk.c
    uint256.c)

  add_subdirectory(ux)

else()

  add_compile_options(-DOS_LITTLE_ENDIAN)

  message(STATUS "Building native binaries")

  if(NOT DEFINED ENV{SPECULOS_DIR})
    message(FATAL_ERROR "Please set SPECULOS_DIR environment variable")
  endif()

  if(NOT DEFINED ENV{BOLOS_SDK_DIR})
    message(FATAL_ERROR "Please set BOLOS_SDK_DIR environment variable")
  endif()

  set(SPECULOS_DIR "$ENV{SPECULOS_DIR}" CACHE INTERNAL "Copied from environment variable")
  set(BOLOS_SDK_DIR "$ENV{BOLOS_SDK_DIR}" CACHE INTERNAL "Copied from environment variable")

  add_compile_definitions(HAVE_NES_CRYPT HAVE_ST_EDES_PLUS HAVE_ST_AES HAVE_CRC HAVE_HASH HAVE_RIPEMD160 HAVE_SHA224 HAVE_SHA256 HAVE_SHA3 HAVE_SHA384 HAVE_SHA512 HAVE_SHA512_WITH_BLOCK_ALT_METHOD HAVE_SHA512_WITH_BLOCK_ALT_METHOD_M0 HAVE_BLAKE2 HAVE_GROESTL HAVE_HMAC HAVE_PBKDF2 HAVE_DES HAVE_AES HAVE_MATH HAVE_RNG HAVE_RNG_RFC6979 HAVE_RNG_SP800_90A HAVE_ECC HAVE_ECC_WEIERSTRASS HAVE_ECC_TWISTED_EDWARDS HAVE_ECC_MONTGOMERY HAVE_SECP256K1_CURVE HAVE_SECP256R1_CURVE HAVE_SECP384R1_CURVE HAVE_SECP521R1_CURVE HAVE_FR256V1_CURVE HAVE_STARK256_CURVE HAVE_BRAINPOOL_P256R1_CURVE HAVE_BRAINPOOL_P256T1_CURVE HAVE_BRAINPOOL_P320R1_CURVE HAVE_BRAINPOOL_P320T1_CURVE HAVE_BRAINPOOL_P384R1_CURVE HAVE_BRAINPOOL_P384T1_CURVE HAVE_BRAINPOOL_P512R1_CURVE HAVE_BRAINPOOL_P512T1_CURVE HAVE_BLS12_381_G1_CURVE HAVE_CV25519_CURVE HAVE_CV448_CURVE HAVE_ED25519_CURVE HAVE_ED448_CURVE HAVE_ECDH HAVE_ECDSA HAVE_EDDSA HAVE_ECSCHNORR HAVE_X25519 HAVE_X448)

  add_library(cxng
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_aead.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_cmac.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_Groestl-ref.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_rng.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_aes.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_crc16.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_hash.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_rng_rfc6979.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_aes_gcm.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_crc32.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_hkdf.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_rsa.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_aes_siv.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_des.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_hmac.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_selftests.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_blake2b.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ecdh.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_math.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_sha256.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_blake3.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ecdsa.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_pbkdf2.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_sha3.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_blake3_ref.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ecfp.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_pkcs1.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_sha512.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_chacha.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ecschnorr.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_poly1305.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_utils.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_chacha_poly.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_eddsa.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ram.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_cipher.c
    ${BOLOS_SDK_DIR}/lib_cxng/src/cx_ripemd160.c
  )
  target_include_directories (cxng PUBLIC ${BOLOS_SDK_DIR}/include ${BOLOS_SDK_DIR}/lib_cxng/include ${BOLOS_SDK_DIR}/target/nanox/include/)

  add_library(speculos
    ${SPECULOS_DIR}/src/bolos/bagl.c
    ${SPECULOS_DIR}/src/bolos/cx_aes.c
    ${SPECULOS_DIR}/src/bolos/cx_aes_sdk2.c
    ${SPECULOS_DIR}/src/bolos/cx_blake2b.c
    ${SPECULOS_DIR}/src/bolos/cx_bn.c
    ${SPECULOS_DIR}/src/bolos/cx.c
    ${SPECULOS_DIR}/src/bolos/cx_crc.c
    ${SPECULOS_DIR}/src/bolos/cx_curve25519.c
    ${SPECULOS_DIR}/src/bolos/cx_ec.c
    ${SPECULOS_DIR}/src/bolos/cx_ec_domain.c
    ${SPECULOS_DIR}/src/bolos/cx_ecpoint.c
    ${SPECULOS_DIR}/src/bolos/cx_ed25519.c
    ${SPECULOS_DIR}/src/bolos/cx_hash.c
    ${SPECULOS_DIR}/src/bolos/cx_hkdf.c
    ${SPECULOS_DIR}/src/bolos/cx_hmac.c
    ${SPECULOS_DIR}/src/bolos/cxlib.c
    ${SPECULOS_DIR}/src/bolos/cx_math.c
    ${SPECULOS_DIR}/src/bolos/cx_montgomery.c
    ${SPECULOS_DIR}/src/bolos/cx_mpi.c
    ${SPECULOS_DIR}/src/bolos/cx_ripemd160.c
    ${SPECULOS_DIR}/src/bolos/cx_rng_rfc6979.c
    ${SPECULOS_DIR}/src/bolos/cx_scc.c
    ${SPECULOS_DIR}/src/bolos/cx_sha256.c
    ${SPECULOS_DIR}/src/bolos/cx_sha3.c
    ${SPECULOS_DIR}/src/bolos/cx_sha512.c
    ${SPECULOS_DIR}/src/bolos/cx_twisted_edwards.c
    ${SPECULOS_DIR}/src/bolos/cx_utils.c
    ${SPECULOS_DIR}/src/bolos/cx_weierstrass.c
    ${SPECULOS_DIR}/src/bolos/default.c
    ${SPECULOS_DIR}/src/bolos/endorsement.c
    ${SPECULOS_DIR}/src/bolos/os_1.2.c
    ${SPECULOS_DIR}/src/bolos/os_1.5.c
    ${SPECULOS_DIR}/src/bolos/os_1.6.c
    ${SPECULOS_DIR}/src/bolos/os_2.0.c
    ${SPECULOS_DIR}/src/bolos/os_bip32.c
    ${SPECULOS_DIR}/src/bolos/os.c
    ${SPECULOS_DIR}/src/bolos/os_eip2333.c
    ${SPECULOS_DIR}/src/bolos/seproxyhal.c

    native/speculos.c
  )
  target_compile_definitions(speculos PUBLIC IMPORT_SPECULOS_HEADERS)

  target_include_directories (speculos PUBLIC ${SPECULOS_DIR}/src/ ${SPECULOS_DIR}/src/bolos/)

  add_library(sdk
    crypto.c
    native/ecall-native.c
    native/ecall-vm.c
    sdk.c
    uint256.c
    ../../vm/src/ecall_bolos.c
    ../../vm/src/ecall_hash.c
    ../../vm/src/uint256.c
    )

  add_subdirectory(ux)

  target_include_directories (sdk PUBLIC native/ ${BOLOS_SDK_DIR}/include ${BOLOS_SDK_DIR}/lib_cxng/include ${BOLOS_SDK_DIR}/target/nanox/include/)
endif()
