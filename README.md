# Text Encryption CLI Tool

A simple command-line tool for encrypting and decrypting text messages using AES-256-CBC encryption. Cross-platform support for Windows and macOS.

## Prerequisites

- C++17 or later
- CMake 3.10 or later
- OpenSSL development libraries

### Installing Dependencies

#### Windows
1. Install [Visual Studio 2019 or later](https://visualstudio.microsoft.com/downloads/) with "Desktop development with C++" workload
2. Install [CMake](https://cmake.org/download/)
3. Install [vcpkg](https://vcpkg.io/en/getting-started.html) for package management
4. Install OpenSSL using vcpkg:
   ```powershell
   vcpkg install openssl:x64-windows
   ```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev
```

#### macOS (using Homebrew)
```bash
brew install cmake openssl@3
```

## Building the Project

### Windows (Command Prompt)
```cmd
mkdir build
cd build
cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake ..
cmake --build . --config Release
```

### Windows (PowerShell)
```powershell
mkdir build
cd build
cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ..
cmake --build . --config Release
```

### Linux/macOS
```bash
mkdir -p build
cd build
cmake ..
make
```

The executable will be in the `build/bin` directory (or `build/Release` on Windows).

## Usage

### Windows (Command Prompt/PowerShell)
```
encrypt_cli.exe [options]
```

### Linux/macOS
```bash
./encrypt_cli [options]
```

### Generate a New Encryption Key
```
encrypt_cli --generate-key
```
This will output a hexadecimal key. Save this key securely as you'll need it to decrypt messages.

### Encrypt a Message
```
encrypt_cli --encrypt "Your secret message" --key <your_hex_key>
```

### Decrypt a Message
```
encrypt_cli --decrypt <encrypted_message> --key <your_hex_key>
```

## Examples

### Windows Examples
```cmd
REM Generate a new key
encrypt_cli.exe -g

REM Encrypt a message
encrypt_cli.exe -e "Secret message" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef

REM Decrypt a message
encrypt_cli.exe -d "U2FsdGVkX1+3qJ8F8Q8fX7Z9LmNOPQ==" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
```

### Linux/macOS Examples
```bash
# Generate a new key
./encrypt_cli -g

# Encrypt a message
./encrypt_cli -e "Secret message" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef

# Decrypt a message
./encrypt_cli -d "U2FsdGVkX1+3qJ8F8Q8fX7Z9LmNOPQ==" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
```

## Examples

1. Generate a key:
   ```bash
   $ ./encrypt_cli -g
   Generated key (hex): 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
   Save this key securely! You'll need it to decrypt your messages.
   ```

2. Encrypt a message:
   ```bash
   $ ./encrypt_cli -e "Hello, World!" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
   Encrypted: U2FsdGVkX1+3qJ8F8Q8fX7Z9LmNOPQ==
   ```

3. Decrypt a message:
   ```bash
   $ ./encrypt_cli -d "U2FsdGVkX1+3qJ8F8Q8fX7Z9LmNOPQ==" -k 1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef
   Decrypted: Hello, World!
   ```

## Security Notes

- Always keep your encryption key secure and private.
- The same key must be used for both encryption and decryption.
- Losing the key means you won't be able to decrypt your messages.
- On Windows, the tool uses the Windows Crypto API for secure random number generation.
- On Unix-like systems, it uses `/dev/urandom` with OpenSSL as a fallback.
- This tool is for educational purposes. Consider using more robust security solutions for production use.

## Building a Release Version (Windows)

For production use on Windows, you might want to create a standalone executable:

1. Build in Release mode:
   ```
   cmake --build . --config Release
   ```

2. The executable will be in `build/Release/encrypt_cli.exe`

3. You'll need to distribute the following DLLs with your executable:
   - `libcrypto-1_1-x64.dll` (from OpenSSL)
   - `libssl-1_1-x64.dll` (from OpenSSL)
   - `vcruntime140.dll` (from Visual C++ Redistributable)
   - `vcruntime140_1.dll` (from Visual C++ Redistributable)
   - `msvcp140.dll` (from Visual C++ Redistributable)

## Troubleshooting

### Common Issues

#### Windows: "The code execution cannot proceed because VCRUNTIME140_1.dll was not found"
Install the latest [Microsoft Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)

#### OpenSSL Not Found
Make sure OpenSSL is installed and the path is correctly set in CMake. On Windows, use the `-DOPENSSL_ROOT_DIR` flag:
```
cmake -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-windows ..
```

### Building with Different Compilers

#### MinGW
```bash
cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ..
cmake --build .
```

#### Clang (macOS/Linux)
```bash
CC=clang CXX=clang++ cmake ..
make
```

## License

This project is open source and available under the Apache 2.0 License.
