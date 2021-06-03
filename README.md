# Upgraded for the SSTIC

More details [here](https://thalium.github.io/blog/posts/sstic_infra_windows/)

1. Security. Challengers getting an RCE could kill processes of other challengers => Solved by using a different AppContainerProfile for each connection.
2. Security. Challengers getting an RCE could DoS the remote machine by executing processes with huge usage of memory and CPUs => Solved by using a Job limiting the duration, the number of concurrent processes and the amount of memory allowed. These parameters are configurable with the command line.
3. Feature. Challengers now have a private directory where they can read and write. Other participants cannot RW this folder. Implemented with the creation of a folder belonging to the unique AppContainerProfile.
4. Feature. Challengers can retrieve theire private profile during 10 minutes after its creation. This done by generating a unique identifier for each challenger. The challenger decides if he wants to retrieve its private folder by entering its identifier, or he can decide to create a new folder. 

# AppJailLauncher (Rust)

AppJailLauncher is akin to a simple version of **xinetd** for Windows but with sandboxing enabled for the spawned child processes. The sandboxing is accomplished via [AppContainers](https://goo.gl/5gNlUy). This project is a rewrite of an [earlier version](https://github.com/trailofbits/AppJailLauncher) in C.

### Tested Platforms
 * Windows 10 Professional x64 (build 14393.1198)
 * Windows 10 Professional x64 (build 15063.296)

### Supported Platforms
 * Windows 8 and above
 * Windows Server 2012 and above
 
## Creating Challenges

There is an example challenge template in `example/` that can be built using CMake.

To build the example challenge:

```
> cd example
> mkdir build
> cd build
> cmake ..
> cmake --build .
```

After building the example challenge, you serve the challenge via the following command in the root of the repository:

```
> .\target\debug\appjaillauncher-rs.exe run --key .\unittest_support\pub\key2.txt .\example\build\Debug\example_challenge.exe
```

## Frequently Asked Questions

#### In the example challenge, what does `InitChallenge` do?
The `InitChallenge` function will create an timer that will terminate the process after a specified amount of milliseconds and  set `stdout` buffering options to work better with network sockets. The first part is essential for countering griefing operations directed at your challenges by malicious actors.

#### I think I broke something. Is there a way to get more logging?
AppJailLauncher uses `env_logger` for logging. This means you can get more debug logging by setting the `RUST_LOG` environment variable to `debug`. For example, in PowerShell, the following command would be sufficient: 
<pre>
> $env:RUST_LOG="debug"
</pre>

#### How do I target x86 Windows from x64 Windows with Rust?
`rustup` should be part of the default Rust install. First, use `rustup` to add the new x86 target:

```
> rustup target add i686-pc-windows-msvc
```

After installation, add `--target=i686-pc-windows-msvc` to the `cargo build`, `cargo test` commands to build for x86.

#### I have a complex ACL setup for my key, why won't things work?
Our ACL implementation is simple and should work on _most_ configurations. However, it is entirely possible that for complex ACL setups, this will not work as intended. If you run into any issues, file an issue.

#### `cargo build` complains that `msvc targets depend on msvc linker but "link.exe" was not found`
You need to install the [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe) or newer.

## Development
[Install Rust](https://www.rust-lang.org/en-US/install.html), then:

Build AppJailLauncher: `cargo build`

Run the unit tests: `cargo test`

## Authors
 * [Andy Ying](https://github.com/yying)
