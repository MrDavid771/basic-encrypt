cmake_minimum_required(VERSION 3.10)
project(TextEncryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Platform-specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Target Windows 7 and later
    add_compile_definitions(NOMINMAX)  # Disable min/max macros
    add_compile_definitions(UNICODE _UNICODE)  # Enable Unicode
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)  # For shared libraries
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(encrypt_cli 
    src/main.cpp
    src/encryptor.cpp
    include/encryptor.h
)

# Platform-specific linking
if(WIN32)
    target_link_libraries(encrypt_cli PRIVATE ws2_32 crypt32)
    
    # Set Windows-specific compiler options
    target_compile_options(encrypt_cli PRIVATE 
        $<$<CONFIG:>:/MT>         # Release
        $<$<CONFIG:Debug>:/MTd>   # Debug
    )
else()
    find_package(Threads REQUIRED)
    target_link_libraries(encrypt_cli PRIVATE Threads::Threads)
    
    if(APPLE)
        # Additional macOS specific settings
        target_link_libraries(encrypt_cli PRIVATE "-framework Security" "-framework CoreFoundation")
    endif()
endif()

# Link OpenSSL libraries
target_link_libraries(encrypt_cli PRIVATE OpenSSL::Crypto OpenSSL::SSL)

# Installation
install(TARGETS encrypt_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
