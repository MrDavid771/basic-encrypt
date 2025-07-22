#include "../include/encryptor.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

#ifdef _WIN32
    #include <wincrypt.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "crypt32.lib")
#else
    #include <unistd.h>
    #include <fcntl.h>
#endif

using namespace std;

bool Encryptor::secure_random_bytes(unsigned char* buffer, size_t size) {
#ifdef _WIN32
    // Use Windows CryptGenRandom for better security on Windows
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        // Fallback to OpenSSL if CryptAcquireContext fails
        return RAND_bytes(buffer, static_cast<int>(size)) == 1;
    }
    
    BOOL success = CryptGenRandom(hCryptProv, static_cast<DWORD>(size), buffer);
    CryptReleaseContext(hCryptProv, 0);
    return success == TRUE;
#else
    // On Unix-like systems use /dev/urandom or OpenSSL as fallback
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t result = read(fd, buffer, size);
        close(fd);
        if (static_cast<size_t>(result) == size) {
            return true;
        }
    }
    // Fallback to OpenSSL if /dev/urandom fails
    return RAND_bytes(buffer, static_cast<int>(size)) == 1;
#endif
}

string Encryptor::generate_key() {
    unsigned char key[32]; // 256 bits
    if (!secure_random_bytes(key, sizeof(key))) {
        throw runtime_error("Failed to generate secure random key");
    }
    return string(reinterpret_cast<char*>(key), sizeof(key));
}

void Encryptor::derive_key_and_iv(const string& key, 
                                 vector<unsigned char>& derived_key,
                                 vector<unsigned char>& iv) {
    // Use SHA-256 to derive a key and IV from the input key
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw runtime_error("Failed to create message digest context");
    }
    
    unsigned int hash_len;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, key.data(), key.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to derive key and IV");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // First half for key, second half for IV
    derived_key.assign(hash.begin(), hash.begin() + 32);
    iv.assign(hash.begin() + 16, hash.begin() + 32);
}

string Encryptor::encrypt(const string& plaintext, const string& key) {
    vector<unsigned char> derived_key, iv;
    derive_key_and_iv(key, derived_key, iv);
    
    // Initialize OpenSSL error strings
    ERR_clear_error();
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create cipher context");
    }

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                              derived_key.data(), iv.data()) != 1) {
            throw runtime_error("Encryption initialization failed");
        }

        // Add padding
        int len;
        int ciphertext_len;
        vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                             reinterpret_cast<const unsigned char*>(plaintext.data()), 
                             plaintext.size()) != 1) {
            throw runtime_error("Encryption failed");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            throw runtime_error("Encryption finalization failed");
        }
        ciphertext_len += len;
        
        // Convert to base64 for easier handling
        BIO *bio = nullptr, *b64 = nullptr;
        BUF_MEM *bufferPtr = nullptr;

        b64 = BIO_new(BIO_f_base64());
        if (!b64) throw runtime_error("Failed to create BIO for base64");
        
        bio = BIO_new(BIO_s_mem());
        if (!bio) {
            BIO_free(b64);
            throw runtime_error("Failed to create BIO for memory");
        }
        
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        
        if (BIO_write(bio, ciphertext.data(), ciphertext_len) <= 0) {
            BIO_free_all(bio);
            throw runtime_error("Failed to write data to BIO");
        }
        
        if (BIO_flush(bio) != 1) {
            BIO_free_all(bio);
            throw runtime_error("Failed to flush BIO");
        }
        
        // Get the memory buffer
        BIO_get_mem_data(bio, (char**)&bufferPtr);
        if (!bufferPtr || !bufferPtr->data || bufferPtr->length == 0) {
            BIO_free_all(bio);
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to get encrypted data from BIO");
        }
        
        string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        EVP_CIPHER_CTX_free(ctx);
        
        return result;
    } catch (const exception& e) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw;
    } catch (...) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Unknown error during encryption/decryption");
    }
}

string Encryptor::decrypt(const string& ciphertext, const string& key) {
    // Decode base64 first
    BIO *bio = nullptr, *b64 = nullptr;
    vector<unsigned char> decoded(ciphertext.size() * 3 / 4 + 1);  // Allocate enough space for decoded data
    int decoded_len = 0;
    
    try {
        b64 = BIO_new(BIO_f_base64());
        if (!b64) throw runtime_error("Failed to create BIO for base64");
        
        bio = BIO_new_mem_buf(ciphertext.data(), static_cast<int>(ciphertext.size()));
        if (!bio) {
            BIO_free(b64);
            throw runtime_error("Failed to create BIO for memory buffer");
        }
        
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        
        decoded_len = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));
        if (decoded_len <= 0) {
            BIO_free_all(bio);
            throw runtime_error("Failed to decode base64 data");
        }
        
        BIO_free_all(bio);
    } catch (...) {
        if (bio) BIO_free_all(bio);
        else if (b64) BIO_free(b64);
        throw;
    }
    
    vector<unsigned char> derived_key, iv;
    derive_key_and_iv(key, derived_key, iv);
    
    // Initialize OpenSSL error strings
    ERR_clear_error();
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create cipher context");
    }

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                              derived_key.data(), iv.data()) != 1) {
            throw runtime_error("Decryption initialization failed");
        }

        int len;
        int plaintext_len;
        vector<unsigned char> plaintext(decoded_len + AES_BLOCK_SIZE);
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                             decoded.data(), decoded_len) != 1) {
            throw runtime_error("Decryption failed");
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            throw runtime_error("Decryption finalization failed - incorrect key?");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    } catch (const exception& e) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw;
    } catch (...) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Unknown error during encryption/decryption");
    }
}
