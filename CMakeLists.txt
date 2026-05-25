cmake_minimum_required(VERSION 3.15)
project(tls_cert_verifier VERSION 0.01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD  17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

find_package(OpenSSL REQUIRED)
add_executable(cert_verifier src/main.cxx)
target_link_libraries(cert_verifier PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(cert_verifier PRIVATE ${OPENSSL_INCLUDE_DIR})
