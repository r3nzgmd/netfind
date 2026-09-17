# NetFind
## Description
NetFind is a Rust library/crate that provides functions to list all devices in your LAN network.  

## Installation
In your project directory, add the crate by typing:
```bash
cargo add netfind
```
Or, you can manually edit your Cargo.toml and add `netfind = "1.0.1"` under the `[dependencies]` tab.

## Usage
The library provides 2 functions:
* `scan()` - returns Option<Vec<Device>> of all devices found in your LAN - that includes IPv4 address and MAC address.
* `list()` - prints found devices list on the screen.
