JFPG is a smaller, greatly simplified, and more modern replacement
for the GPG/PGP encryption utility. It offers
a more or less similar  syntax for encryption,
decryption, signing, and verification. It uses
Dan Bernstein's Tweetnacl crypto library. JFPG
only uses  modern, high speed crypto primitives 
and all encryption is authenticated by default. 
However, this means it is not backwards-compatible
with GPG/PGP (probably a feature, not a bug). 
There are no interactive commands, which makes
JFPG easy to include in shell scripts.

JFPG should compile on any Unix-like system without any
dependencies, but I have only tested it on OpenBSD so far.
To compile, simply run "make".

Command syntax

	-new keypairs:         jfpg -n new-key-id
	-sign:                 jfpg -s -f file -x signing-secret-key
	-verify sig:   	       jfpg -v -f file -x signing-public-key
	-encrypt/decrypt:      jfpg [-e | -d] -f file -p encryption-pubkey -k encryption-secretkey 


You will need to create a new set of keys when you first use JFPG. 
This creates 2 keypairs, a pair of Curve25519 keys for encryption/decryption
and a pair of Ed25519 keys for signing. It takes your desired key ID
 (probably your name) as its only option.

Primitives used

	-Signing: Ed25519
	-Asymmetric encryption/decryption: Curve25519
	-Symmetric cipher: Xsalsa20-Poly1305

Limitations

	-Secret keys are not encrypted. This allows them to be used without
	 passwords, but is somewhat less secure. However, JFPG cannot secure
	 your computer for you. Even encrypted secret keys are not safe if you
	 are running JFPG on a compromised machine.

	-There is no forward secrecy (yet). A given sender/receiver pair will
	 calculate the same shared symmeric key for all their messages. 

An experimental demo script showing automatic encryption/decryption of files sent to Google drive is provided.
It requires the gdrive command line tool if you want to try it. 
