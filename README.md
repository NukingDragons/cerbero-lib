<!-- cargo-sync-readme start -->

# Cerbero

[![Crates.io](https://img.shields.io/crates/v/cerbero-lib)](https://crates.io/crates/cerbero-lib)
[![Language Rust](https://img.shields.io/badge/Language-Rust-blue)](https://www.rust-lang.org/)

Library to perform several tasks related with Kerberos protocol in an Active Directory pentest.

This repo was cloned from <https://gitlab.com/Zer1i0/cerbero> and has been converted into a library format.
I intend to add more features/clean up the code further, see the [TODO](#TODO) section.

## Installation

To use this library in your project you can add it via `cargo add`:

```sh
cargo add cerbero-lib
```

## Functions
- [ask](#ask)
- [asreproast](#asreproast)
- [brute](#brute)
- [convert](#convert)
- [craft](#craft)
- [hash](#hash)
- [kerberoast](#kerberoast)

### Ask
The `ask` command allows to retrieve Kerberos tickets (TGT/TGS) from the KDC
(Domain Controller in Active Directory environment). Moreover, it also
perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
Kerberos extensions.

See the [example](examples/ask/src/main.rs)

### AsRepRoast
`asreproast` can be used to discover users that do not require
pre-authentication and retrieve a ticket to crack with hashcat or john.

See the [example](examples/asreproast/src/main.rs)

### Brute
`brute` performs TGTs requests in order to discover user credentials
based on the KDC response. This bruteforce technique allows you to
discover:
+ Valid username/password pairs
+ Valid usernames
+ Expired passwords
+ Blocked or disabled users

This attack should be performed carefully since can block user
accounts in case of perform many incorrect authentication attemps
for the same user.

See the [example](examples/brute/src/main.rs)

### Convert
`convert` ticket files between krb (Windows) and
ccache (Linux) formats.

See the [example](examples/convert/src/main.rs)

### Craft
To `craft` golden and silver tickets.

See the [example](examples/craft/src/main.rs)

### Hash
Calculate the Kerberos keys (password hashes) from the user password.

See the [example](examples/craft/hash/main.rs)

### Kerberoast
To format encrypted part of tickets in order to be cracked by hashcat or john.

You need to provide a file with the user services. Each line of the file
must have one of the following formats:
* `user`
* `domain/user`
* `user:spn`
* `domain/user:spn`

When a service [SPN](https://en.hackndo.com/service-principal-name-spn/)
is not specified, then a
[NT-ENTERPRISE principal](https://swarm.ptsecurity.com/kerberoasting-without-spns/)
is used. This can also be useful to bruteforce users with services.

See the [example](examples/craft/kerberoast/main.rs)

## TODO
 - Clean up the code, there's a ton of verbose returns that don't need to be there and some double dereferences
 - Make the arguments to the commands more concise
 - Remove some of the allows inside of lib.rs
 - Improve documentation significantly, including README and the examples directory

## Credits
This work is based on great work of other people:
- [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
- [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)
- [Cerbero](https://gitlab.com/Zer1i0/cerbero) of Eloy [@zer1i0](zer1t0ps@protonmail.com)

<!-- cargo-sync-readme end -->
