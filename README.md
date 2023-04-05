# Rust Crypto Funcs for Swift

This repository contains Rust cryptography functions that can be used in Swift applications. The functions are compiled into a static library that can be linked to a Swift application.

## Getting Started

To use the Rust cryptography functions in your Swift project, follow these steps:

1. Clone the repository:
```sh
git clone https://github.com/coin-shuffle/crypto-bridge.git
```

2. Build the Rust static library:
```sh
cd crypto-bridge
cargo lipo --release
```

3. Copy the library to your Swift project:
```sh
cp target/universal/release/libcrypto.a /path/to/your/swift/project/
```

4. In your Xcode project, add the Rust library to the project by selecting "Add files to [project name]" from the "File" menu.

5. In your Swift code, import the Rust functions:
```sh
import crypto_bridge
```

6. Call the Rust functions as needed.

## Requirements

* Rust version 1.50.0 or later.
* Xcode version 10.2 or later.
* iOS deployment target version 9.0 or later.

## Tutorial

If you need more detailed instructions on how to use Rust in your iOS application, check out this [tutorial](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html) provided by Mozilla. It covers the process of setting up Rust on iOS, creating a Rust static library, and integrating it into a Swift application.

## License

This project is licensed under the Apache-2 License - see the [LICENSE](LICENSE) file for details.
