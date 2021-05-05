# lecnet
lecnet C++ network library

<p>
  <img alt="Lines of code" src="https://img.shields.io/tokei/lines/github/alecmus/lecnet">
  <img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/alecmus/lecnet">
  <img alt="GitHub closed issues" src="https://img.shields.io/github/issues-closed-raw/alecmus/lecnet">
</p>

#### Release Info
<p>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/alecmus/lecnet">
  <img alt="GitHub Release Date" src="https://img.shields.io/github/release-date/alecmus/lecnet">
  <img alt="GitHub all releases" src="https://img.shields.io/github/downloads/alecmus/lecnet/total">
</p>

#### Commit Info
<p>
  <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/alecmus/lecnet">
  <img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/y/alecmus/lecnet">
</p>

### About the Library
The lecnet library is a networking library designed for the rapid development of modern, efficient and easy to maintain C++ networking applications. It is part of the liblec libraries (https://github.com/alecmus/liblec).

### Documentation
The library uses embedded XML-style documentation. An HTML version of this documentation is available [here](https://alecmus.github.io/lecnet).

### Prebuilt Binaries
Prebuild binaries of the library can be found under releases: https://github.com/alecmus/lecnet/releases.

### Dependencies

#### OpenSSL
This library uses OpenSSL (https://www.openssl.org/) for various functions, e.g. SSL encryption and making digital certificates. The user is free to compile OpenSSL on their own, but for convenience, OpenSSL binaries that I have compiled can be obtained from https://github.com/alecmus/files/tree/master/openssl. Kindly note that I prefer compiling OpenSSL so that the 32 and 64 bit binaries have different names to avoid ambiguity and deployment mistakes and,a also for other advantages that I won't get into here.

By default, the lecnet project is configured to look for OpenSSL in C:\local\libs\openssl. Placing the OpenSSL files I compiled into this location will enable building without modifications; placing them (or differently named variants) elsewhere will require appropriate modification of the project properties and source files.

### Building
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

### Linking to the Library

#### Microsoft Visual Studio
Open your project's properties and for All Configurations and All Platforms set the following:
1. C/C++ -> General -> Additional Include Directories -> Edit -> New Line ... add \liblec\include
2. Linker -> General -> Additional Library Directories -> Edit -> New Line ... add \liblec\lib
3. Debugging -> Environment -> Edit ... add PATH=\liblec\bin;\openssl\bin;PATH%

Now you can use the required functions by calling #include <liblec/lecnet/...>

Build.

### Using the Library
Usage guidelines are available in-code in the respective header files. Below are minimalistic example programs.

#### TCP/IP Server
Below is sample code for implementing a TCP/IP server (with default parameters):

```
#include <liblec/lecnet/tcp.h>
#include <thread>
#include <chrono>
#include <iostream>

class tcp_server : public liblec::lecnet::tcp::server_async {
public:
    void log(const std::string& time_stamp, const std::string& event) override {
        std::cout << time_stamp + ": " << event << std::endl;
    }

    std::string on_receive(const client_address& address,
        const std::string& data_received) override {
        return data_received;
    }
};

int main() {
    liblec::lecnet::tcp::server::server_params params;
    
    tcp_server server;
    if (server.start(params)) {
        while (server.starting())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

        while (server.running())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

        server.stop();
    }

    return 0;
}
```
The code above results in the following output:
![](https://github.com/alecmus/files/blob/master/liblec/lecnet/screenshots/lecnet_1.0.0_screenshot_01.PNG?raw=true)

#### TCP/IP Client
Below is sample code for implementing a TCP/IP client (with default parameters):

```
#include <liblec/lecnet/tcp.h>
#include <thread>
#include <chrono>
#include <iostream>

int main() {
    liblec::lecnet::tcp::client::client_params params;
    params.use_ssl = false;
    liblec::lecnet::tcp::client client;
    std::string error;
    if (client.connect(params, error)) {
        while (client.connecting())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (client.connected(error)) {
            while (client.running()) {
                std::string received;
                if (client.send_data("Sample message", received, 10, nullptr, error))
                    std::cout << "Reply from server: " << received << std::endl;

                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
        else
            std::cout << error << std::endl;
    }
    
    return 0;
}
```
The code above results in the following output:
![](https://github.com/alecmus/files/blob/master/liblec/lecnet/screenshots/lecnet_1.0.0_screenshot_02.PNG?raw=true)

### Deploying your Application
If it's a 32 bit build you will need to deploy it with lecnet32.dll in the same folder, together with libeay32.dll (32bit build of OpenSSL). If it's a 64 bit build use the lecnet64.dll, together with libeay64.dll (64 bit build of OpenSSL).
