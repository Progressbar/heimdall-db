Heimdall - database
===================

This crate handles retrieving and management of NFC tags and members of [Progressbar hackerspace](https://progressbar.sk) in Heimdall access system.
Separation of this logic into it's own crate allows developing it without access to physical hardware (outside of Progressbar).

The code aims to be idiomatic Rust with as little unsafes as possible. It's still WIP, but should be usable for basic things (opening the door) now.
