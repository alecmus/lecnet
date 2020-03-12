# lecnet
lecnet C++ network library

## ABOUT THE LIBRARY
The lecnet library is a networking library designed for the rapid development of modern, efficient and easy to maintain C++ networking applications. It is part of the liblec libraries (https://github.com/alecmus/liblec).

## PREBUILT BINARIES
Prebuild binaries of the library can be found under releases: https://github.com/alecmus/lecnet/releases.

## DEPENDENCIES

### OpenSSL
This library uses OpenSSL (https://www.openssl.org/) for various functions, e.g. SSL encryption and making digital certificates. The user is free to compile OpenSSL on their own, but for convenience, OpenSSL binaries that I have compiled can be obtained from https://github.com/alecmus/files/tree/master/openssl. Kindly note that I prefer compiling OpenSSL so that the 32 and 64 bit binaries have different names to avoid ambiguity and deployment mistakes and,a also for other advantages that I won't get into here.

By default, the lecnet project is configured to look for OpenSSL in C:\local\libs\openssl. Placing the OpenSSL files I compiled into this location will enable building without modifications; placing them (or differently named variants) elsewhere will require appropriate modification of the project properties and source files.

## BUILDING
Create a folder '\liblec' and clone the repository into it such that it resides in 'liblec\lecnet'. Open the Microsoft Visual Studio Solution file liblec\lecnet\lecnet.sln. Select Build -> Batch Build, then select the desired configurations of the given four:
1. Debug x86
2. Relese x86 (32 bit Release Build)
3. Debug x64
4. Release x64 (64 bit Release Build)

Build.

Three folders will be created in the \liblec directory, namely bin, lib and include. Below is a description of these subdirectories.

1. bin - contains the binary files. The following files will be created:

File            | Description
--------------- | ------------------------------------
lecnet32.dll    | 32 bit release build
lecnet64.dll    | 64 bit release build
lecnet32d.dll   | 32 bit debug build
lecnet64d.dll   | 64 bit debug build

2. lib - contains the static library files that accompany the dlls. The files are names after the respective dlls.
3. include - contains the include files

## LINKING TO THE LIBRARY

### Microsoft Visual Studio
Open your project's properties and for All Configurations and All Platforms set the following:
1. C/C++ -> General -> Additional Include Directories -> Edit -> New Line ... add \liblec\include
2. Linker -> General -> Additional Library Directories -> Edit -> New Line ... add \liblec\lib
3. Debugging -> Environment -> Edit ... add PATH=\liblec\bin;\openssl\bin;PATH%

Now you can use the required functions by calling #include <liblec/lecnet/...>

Build.

## DEPLOYING YOUR APPLICATION
If it's a 32 bit build you will need to deploy it with lecnet32.dll in the same folder, together with libeay32.dll (32bit build of OpenSSL). If it's a 64 bit build use the lecnet64.dll, together with libeay64.dll (64 bit build of OpenSSL).
