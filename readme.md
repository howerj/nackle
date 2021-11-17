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

# References

* <https://news.ycombinator.com/item?id=7727738>
* <https://tinyssh.org/>
* <https://tweetnacl.cr.yp.to/>
* <https://nullprogram.com/blog/2021/01/30/>
