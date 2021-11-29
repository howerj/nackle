# Crypto Tools

* Author: Richard James Howe
* Project: Crypto tools built upon TweetNaCl
* License: Public Domain
* Repo: <https://github.com/howerj/crypto>

# Notes

The first main task it to create a set of tools much like;
<https://github.com/sbp/tweetnacl-tools>. The first version will
be a replica of those tools, which have an unfortunate limitation
of attempting to allocate enough memory for the entire file in
memory before encrypting/decrypting files instead of processing
the file chunk by chunk. A different (and unfortunately slightly
more complicated) scheme must be made to handle this.

The second goal will be to make a replacement for SSL/TLS,
more suitable for constrained and embedded systems, that is
much simpler to use, with much less memory usage.

Given that I am a cryptographic amateur with enough knowledge
to be dangerous this repository should be *NOT* be used for
production purposes.

# To Do

* [ ] Library of cross-platform command line tools for:
  * [ ] Encryption/Decryption
  * [x] CSRNG using block cipher and available as a utility
  for cross platform random number generation support using
  a seed (with major caveats).
  * [x] Brain-wallet password creator
  * [ ] Integrate <https://github.com/sbp/tweetnacl-tools/pull/1/files>
  * [ ] Remove standard in/output special behaviour. Add two tools
    for turning output into PGP like email message format.
  * [ ] Make sure argument placement is consistent and that
     the command line tools are easy to use and difficult to misuse.
* TweetNaCl
  * [ ] Modify TweetNaCl so it includes the functions it says it exports
  * [ ] Add a way of getting data from streams instead of buffers to
    allow arbitrary length input whilst still exporting the previous
    symbols.
* [ ] Simpler Replacement for SSL/TLS
* [ ] Test suite for all components
* [ ] Install/Uninstall scripts (makefile)
* [ ] GPG like Email tools
* [ ] Documentation
  * [ ] Manual pages
  * [ ] Document design decisions so they can be reviewed/changed.
* [ ] Rename library: crypto -> nackle
  * [ ] Make one big tool "nackle", for doing everything. Or not?
* [ ] Make a file format? Or keep it as is for simplicity?

# Rough design goals  for TLS/SSL replacement

The design will likely be incorrect and flawed until the protocol is
in more use, and people will find problems with it. This was certainly
the case with SSL/TLS, the main problem will be getting people to use
the protocol enough that it starts to be integrated into other systems
such as MQTT/Git/HTTP/etcetera. The phrase "Do not roll your own
crypto" *used* to mean do not make your own crypto algorithms, and
instead use existing ones to build your own protocols. It has since
become an excuse (with valid reasons) to not improve on existing protocols
at all.

This protocol and cryptographic tool suite is meant to be:

* Use few resources.
* Simple and Small.

More concretely; There will be little or no configuration, the 
defaults should be secure, it should be possible to port the library
to resource constrained systems (SSL/TLS requires many tens of
kilobytes in the worst case, and requires lots of flash space to
store all the various combinations of algorithms that are possible).

The primary use case is IoT platforms.

It will not support certificate expiry (which seems to be more
of a money making scheme that has the consequence of lots of IoT
devices become junk given a long enough time line).

The user should not need to care about what ciphers are or are
not supported, nor configuring obscure parameters (it almost seems
crypto libraries have been deliberately engineered to be as
complex as possible...perhaps Hanlon's Razor is suitable here,
perhaps not).

Anything more complex than a single function called "connect"
that takes a single parameter (the address to connect to) puts
barriers up that will make programmers more apprehensive to use
secure systems. Unfortunately we will have to make a function
that is a little more complex than this, but that should be the
goal.

Options that should be supported (with a bitmask of options):

* INSECURE mode (OFF by default); do all the cryptography but
trust any of the certs.
* SAVE-CERT  (OFF by default); use the certificate the server
provides, and store it (failing if this is not possible) if
we do not have a certificate already for this server, preventing
future attacks (but allowing them on this session).
* ALLOW-KEY-CHANGE-SERVER (OFF by default); part of a mechanism to allow the update
of cryptographic credentials, which will allow the server to
change its public keys stored on the client.
* ALLOW-KEY-CHANGE-CLIENT (OFF by default); allow the 
*SERVER* to change the *CLIENTS* keys.

Other notes:

* Diffie-Hellman should be used to generate an ephemeral key,
which should be non-optional.
* Fixed sized packets should be exchanged, all commands encrypted
and authenticated.
* All of the various attacks on SSL/TLS should be investigated
to try to design something that can be mitigated against them.
* There should be no way to downgrade a connection.
* Where, what, how, for the certificate chains needs to be
decided, but other things apart from domains could be signed
as well (MAC addresses, IPs, domains, and arbitrary info).
* Bindings for other languages should be made (C, C++, Rust,
Java, C#, python, JavaScript, should cover most languages).
* Ideally only the public/private key-pair should be used for
most operations, meaning certificates should not be required,
both to identify the client, and for the server, if this is
possible.
* Other simple services could be provided by the server (Time
for instance).

# References

* <https://news.ycombinator.com/item?id=7727738>
* <https://tinyssh.org/>
* <https://tweetnacl.cr.yp.to/>
* <https://nullprogram.com/blog/2021/01/30/>
