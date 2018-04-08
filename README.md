<a href="https://scan.coverity.com/projects/jsfierro-jfpg">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/15272/badge.svg"/>
</a>

*DISCLAIMER: I made every effort to write this securely
but I can't make any guarantees. Use it at your own risk.
This is an alpha version. I will probably make changes
that are not backwards compatible. Don't use it on anything 
you want to decrypt later just yet.*

Introduction
------------

jfpg is a small file encryption and signing utility 
roughly inspired by GPG/PGP, but compiles with no dependencies. It
offers a more or less similar  syntax for encryption,
decryption, signing, and verification. It uses
Dan Bernstein's TweetNaCL crypto library, thus it
only uses  modern, high speed crypto primitives 
and all encryption is authenticated by default. 
However, this means it is not backwards-compatible
with GPG/PGP (probably a feature, not a bug). 

Compiling
---------
Simply run the following:

		$ make
		# make install


Beginning on 17-June-2017, all commits/tags will be 
cryptographically signed with GPG. You can always
find my current GPG public key [here](https://nonstate.io/about.html).

jfpg should compile on most Unix-like systems without any
dependencies. It has been tested and confirmed to work on 
the following operating systems:

- OpenBSD
- FreeBSD
- Dragonfly BSD
- Ubuntu 14.04
- Ubuntu 16.04
- Fedora 25
- Kali Linux 2016.2
- OS X Yosemite

Usage
-----
See the man page (jfpg.1) for full usage examples.

You will need to create a new set of keys (invoked with the -n option) when you first use jfpg 
for signing/verifying or asymmetric encryption/decryption. 
This will create 2 keypairs, a pair of Curve25519 keys for encryption/decryption
and a pair of Ed25519 keys for signing. It takes your desired key ID
(name, email, etc) as its only required option. Secret keys will be 
separately encrypted and you will be asked to provide a passphrase for each.  

Passphrases are read from the tty by default. The -S option will cause
jfpg to read them from stdin, making it easier to use jfpg in a script.
However, this exposes your passphrase to anyone who can run ps on your machine,
so use it with care.

Key generation and symmetric encryption (using the "-c" option) will
derive the encryption key from a passphrase, using Argon2id. 
The rounds parameter for Argon2 can be invoked with "-r" and the amount of 
RAM used, in mebibytes, can be specified with the "-m" option. The defaults
below are used if you do not specify anything. 

- Default rounds: 2
- Default mem: 1024 MiB
- Default number of threads: 8
- Min rounds: 1
- Max rounds: 1024
- Min mem: 56 MiB
- Max mem: 64 GiB

The defaults work well for fast machines with plenty of RAM, but are
potentially very slow on older single core devices, and will not work
at all on devices with less than 1024 MiB of RAM free. Pick the largest
values that are tolerable for your hardware.

Threat Model
------------

jfpg is designed to secure data that is (or will be) in transit or sitting on 
a remote server. Secret keys are encrypted, however, they should ideally be kept
offline. They remain vulnerable to weak passwords or an attacker with the 
ability to capture your password. Securing your machine against such an attacker
is beyond the scope of jfpg.

 
Primitives used
---------------

- Signing: Ed25519
- Asymmetric key exchange: X25519 key exchange with Curve25519 keys 
- Symmetric cipher: XSalsa20-Poly1305
- Password-based key derivation: Argon2id version 1.3
- Random number generation: arc4random on OpenBSD. /dev/urandom everywhere else

Limitations
-----------

- There is no forward secrecy. A given sender/receiver pair will
	calculate the same shared secret for all of their messages.

- jfpg does not manage keys for you. This is a problem that is likely
	beyond the ability of a command line utility to handle properly. 

As always, if you do find a security problem or bug, 
comments, advice, and/or patches are welcome and appreciated. Thanks!
