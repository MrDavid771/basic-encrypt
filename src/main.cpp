#include "../include/encryptor.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <fcntl.h>
    #include <io.h>
    #define STDIN_FILENO 0
    #define STDOUT_FILENO 1
    #define STDERR_FILENO 2
    #define isatty _isatty
    #define fileno _fileno
#else
    #include <unistd.h>
#endif

using namespace std;

// Function to convert a string to hex representation
string string_to_hex(const string& input) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char c : input) {
        ss << setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

// Function to convert hex string back to string
string hex_to_string(const string& hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(stoi(byteString, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

void print_usage() {
    cout << "Usage: encrypt_cli [options]\n"
         << "Options:\n"
         << "  -e, --encrypt <text>   Encrypt the provided text\n"
         << "  -d, --decrypt <text>   Decrypt the provided text\n"
         << "  -k, --key <key>        Encryption/decryption key in hex format\n"
         << "  -g, --generate-key     Generate a new encryption key\n"
         << "  -h, --help             Show this help message\n"
         << "\nExamples:\n"
         << "  Generate a new key:         encrypt_cli -g\n"
         << "  Encrypt a message:         encrypt_cli -e \"Secret message\" -k <hex_key>\n"
         << "  Decrypt a message:         encrypt_cli -d <encrypted_message> -k <hex_key>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    string mode;
    string text;
    string key_hex;
    bool generate_key = false;

    // On Windows, set binary mode for stdin/stdout to avoid text mode issues
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
        _setmode(_fileno(stderr), _O_BINARY);
    #endif

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "-e" || arg == "--encrypt") {
            if (i + 1 < argc) {
                mode = "encrypt";
                text = argv[++i];
            } else {
                cerr << "Error: No text provided for encryption\n";
                return 1;
            }
        } else if (arg == "-d" || arg == "--decrypt") {
            if (i + 1 < argc) {
                mode = "decrypt";
                text = argv[++i];
            } else {
                cerr << "Error: No text provided for decryption\n";
                return 1;
            }
        } else if (arg == "-k" || arg == "--key") {
            if (i + 1 < argc) {
                key_hex = argv[++i];
            } else {
                cerr << "Error: No key provided\n";
                return 1;
            }
        } else if (arg == "-g" || arg == "--generate-key") {
            generate_key = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage();
            return 0;
        }
    }

    try {
        if (generate_key) {
            string key = Encryptor::generate_key();
            cout << "Generated key (hex): " << string_to_hex(key) << "\n";
            cout << "Save this key securely! You'll need it to decrypt your messages.\n";
            return 0;
        }

        if (mode.empty()) {
            cerr << "Error: No mode specified. Use -e to encrypt or -d to decrypt.\n";
            return 1;
        }

        if (key_hex.empty()) {
            cerr << "Error: No encryption key provided. Use -k to provide a key.\n";
            return 1;
        }

        // Convert hex key back to binary
        string key;
        try {
            key = hex_to_string(key_hex);
        } catch (const exception& e) {
            cerr << "Error: Invalid key format. Key must be a valid hexadecimal string.\n";
            return 1;
        }

        if (mode == "encrypt") {
            string encrypted = Encryptor::encrypt(text, key);
            cout << "Encrypted: " << encrypted << "\n";
        } else if (mode == "decrypt") {
            string decrypted = Encryptor::decrypt(text, key);
            cout << "Decrypted: " << decrypted << "\n";
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
