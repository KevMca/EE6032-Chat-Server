# Dependencies
* Using CMake to create make files
* Using Visual Studio 17 2022 for compiling
* Using vcpkg as the package manager

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
