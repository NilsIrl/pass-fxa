# pass-fxa

[![Crates.io](https://img.shields.io/crates/v/pass-fxa?label=pass-fxa)][crates.io]
[![Crates.io](https://img.shields.io/crates/v/pass-fxa-lib?label=pass-fxa-lib)][crates.io-lib]

A program that uses Firefox's builtin password manager with [zx2c4's
pass][pass].

It is meant to be used instead of other traditional browser extensions such as
[passff] and [Browserpass][browserpass] with the following benefits:

* More portable: there is no need to install native messaging host
* Potentially more secure by reducing some of the attack surface:
  - No native messaging host
  - https://lock.cmpxchg8b.com/passmgrs.html
* The native browser UI is better (anecdotal evidence)

## Installation

### Using pre-built binaries from the CI

Linux, macOS and Windows binaries are available on the [release page]. These
binaries are built by GitHub Actions CI.

### Using `cargo install`

#### From [crates.io]

```sh
cargo install pass-fxa
```

#### From git

```
cargo install --git https://github.com/NilsIrl/pass-fxa.git
```

## Usage

Just run `pass-fxa`. That's it!

`pass-fxa` will attempt to find your firefox credentials by looking for a
password for which the URL is `firefox.com`. It will use these credentials to
then upload your passwords to your Firefox Account (passwords are E2E
encrypted).

If multiple records are available, it is possible to specify which to use:

```sh
pass-fxa --pass-name firefox.com/example@riseup.net
```

It is also possible to remove passwords from FxA if they are in your password
store, effectively reverting the uploading operation:

```sh
pass-fxa [--pass-name <pass-name>] delete
```

### Store format

The URL & username can be obtained in 2 different ways:

1. [As fields in each file][1] `login`, `username`, `user` for the username and
   `url`, `uri`, `website`, `site`, `link` and `launch` for the URL.
2. From the filepath, with the containing folder being the domain and the
   filename the username

For example the following store define logins with username:

* `example@riseup.net` for `github.com`
* `example` for `riseup.net`
* `robert` for `yahoo.com`

```
github.com
  example@riseup.net
email
  riseup.net
    example
  yahoo.com
    robert
```

Records can be explicitly excluded from being uploaded by adding the line `fxa:
exclude` to a password file. It is also possible to only upload some passwords
by adding the line `fxa: include`. Passwords that have as host `firefox.com`
are excluded by default.

## License and Copyright

`pass-fxa` is licensed under the GNU GENERAL PUBLIC LICENSE Version 3 and the
underlying library for communication with FxA, `pass-fxa-lib`, is licensed
under the GNU LESSER GENERAL PUBLIC LICENSE Version 3.

Copyright © 2021-2023 Nils André-Chang

[browserpass]: https://github.com/browserpass/browserpass-extension
[crates.io]: https://crates.io/crates/pass-fxa
[crates.io-lib]: https://crates.io/crates/pass-fxa-lib
[passff]: https://github.com/passff/passff
[pass]: https://www.passwordstore.org/
[release page]: https://github.com/NilsIrl/pass-fxa/releases

[1]: https://github.com/passff/passff#multi-line-format
