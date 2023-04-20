# Dependencies
* Using CMake to create make files
* Using Visual Studio 17 2022 for compiling
* Using vcpkg as the package manager

# File structure
    .
    ├── build               # Compiled files
    ├── certs               # Folder with all public certs and private key files
    ├── include             # Included files that are not main applications
    │   ├── cert.h
    │   ├── encryption.h
    │   ├── logging.h
    │   ├── protocol.h
    ├── logs                # Contains log files for server and client applications
    ├── src                 # Source files for includes and main applications
    │   ├── cert.cpp        # Custom certificate code
    │   ├── client.cpp      # Client application
    │   ├── client.h
    │   ├── encryption.cpp  # Encapsulation of crypto++ library
    │   ├── logging.cpp     # Error and status logging
    │   ├── protocol.cpp    # Message templates for communicating between server and clients
    │   ├── server.cpp      # Server application
    │   ├── server.h
    ├── utils               # C++ applications for creating certificates
    ├── CMakeLists.txt      # CMake file
    ├── vcpkg.json          # VCPKG file
    ├── .gitignore          # Git file
    ├── build.bat           # Batch script for building all applications
    ├── run.bat             # Batch script for running a server and 3 clients

# Building and running

To create build directory:
```
mkdir build
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE="C:\Program Files\vcpkg\scripts\buildsystems\vcpkg.cmake"
```

To build, run the build.bat batch file:
```
.\build.bat
```

To run the applications, run the build.bat batch file:
```
.\run.bat
```
