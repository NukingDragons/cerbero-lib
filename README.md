<!-- cargo-sync-readme start -->

```
  ____          _                          _ _ _
 / ___|___ _ __| |__   ___ _ __ ___       | (_) |__
| |   / _ \ '__| '_ \ / _ \ '__/ _ \ _____| | | '_ \
| |__|  __/ |  | |_) |  __/ | | (_) |_____| | | |_) |
 \____\___|_|  |_.__/ \___|_|  \___/      |_|_|_.__/
```


[![Crates.io](https://img.shields.io/crates/v/cerbero-lib)](https://crates.io/crates/cerbero-lib)
[![Language Rust](https://img.shields.io/badge/Language-Rust-blue)](https://www.rust-lang.org/)

Library to perform several tasks related with the Kerberos protocol in an Active Directory pentest.

This repo was cloned from <https://gitlab.com/Zer1i0/cerbero> and has been converted into a library format.
I intend to add more features/clean up the code further -- view the [TODO](#TODO) section below.

## Table of Contents
1. [**Installation**](#installation)
2. [**Functions**](#functions)
    - [**ask**](#ask)
    - [**asreproast**](#asreproast)
    - [**brute**](#brute)
    - [**convert**](#convert)
    - [**craft**](#craft)
    - [**hash**](#hash)
    - [**kerberoast**](#kerberoast)
3. [**TODO**](#todo)
4. [**Credits**](#credits)

---

## Installation

To use this library in your project you can add it via `cargo add`:

```sh
cargo add cerbero-lib
```

## Functions

### Ask
The `ask` function allows retrieval of Kerberos tickets (TGT/TGS) from the KDC
(Domain Controller in Active Directory environment). Moreover, it also
perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
Kerberos extensions.

_(View the `ask` example [here](examples/ask/src/main.rs))_

### AsRepRoast
The `asreproast` function can be used to discover users that do not require
pre-authentication and retrieve a ticket to crack with hashcat or john.

_(View the `asreproast` example [here](examples/asreproast/src/main.rs))_

### Brute
The `brute` function performs TGT requests in order to discover user credentials
based on the KDC response. This bruteforce technique allows you to discover:
+ Valid username/password pairs
+ Valid usernames
+ Expired passwords
+ Blocked or disabled users

This attack should be performed carefully since can block user
accounts in case of perform many incorrect authentication attemps
for the same user.

_(View the `brute` example [here](examples/brute/src/main.rs))_

### Convert
The `convert` function will convert ticket files between krb (Windows)
and ccache (Linux) formats.

_(View the `convert` example [here](examples/convert/src/main.rs))_

### Craft
The `craft` function allows for the crafting of golden and silver tickets.

_(View the `craft` example [here](examples/craft/src/main.rs))_

### Hash
The `hash` module contains functions that calculate the Kerberos keys (password hashes) from the user password.

_(View the `hash` example [here](examples/hash/src/main.rs))_

### Kerberoast
The `kerberoast` function can be used to retrieve a (potentially crackable) password hash
for an account with an SPN set.

To format encrypted part of tickets in order to be cracked by hashcat or john,
you need to provide a file with the user services. Each line of the file
must have one of the following formats:
* `user`
* `domain/user`
* `user:spn`
* `domain/user:spn`

When a service [SPN](https://en.hackndo.com/service-principal-name-spn/)
is not specified, then a
[NT-ENTERPRISE principal](https://swarm.ptsecurity.com/kerberoasting-without-spns/)
is used. This can also be useful to bruteforce users with services.

_(View the `kerberoast` example [here](examples/kerberoast/src/main.rs))_

## TODO

> [!note]
> - Clean up the code, clippy thinks there are too many args to some functions + large Result types
> - Remove some of the allows inside of lib.rs
> - Improve documentation significantly, including README and the examples directory
> - Add SID lookup module and improve the functions that require them

## Credits
This work is based on great work of other people:
- [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
- [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)
- [Cerbero](https://gitlab.com/Zer1i0/cerbero) of Eloy [@zer1i0](zer1t0ps@protonmail.com)

<!-- cargo-sync-readme end -->
