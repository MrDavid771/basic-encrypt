#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>
#include <vector>
#include <cstdint>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "crypt32.lib")
#endif

class Encryptor {
public:
    // Generate a new encryption key
    static std::string generate_key();
    
    // Encrypt plaintext using the provided key
    static std::string encrypt(const std::string& plaintext, const std::string& key);
    
    // Decrypt ciphertext using the provided key
    static std::string decrypt(const std::string& ciphertext, const std::string& key);

private:
    // Helper function to derive a key and IV from the input key
    static void derive_key_and_iv(const std::string& key, 
                                 std::vector<unsigned char>& derived_key,
                                 std::vector<unsigned char>& iv);
    
    // Platform-specific secure random number generation
    static bool secure_random_bytes(unsigned char* buffer, size_t size);
};

#endif // ENCRYPTOR_H
