# Changelog

## v0.1.1

### Fixed

- **Process abort when a constructor is called without `new`.** Calling an
  algorithm or mode constructor as a plain function (`algorithm.Rijndael128()`
  instead of `new algorithm.Rijndael128()`) redirected through the stored
  constructor with `Nan::NewInstance(...).ToLocalChecked()`. On current V8 that
  re-entrant `NewInstance`, on a template that uses `Inherit`, can return an
  empty `MaybeLocal`, and `ToLocalChecked` on empty is a fatal abort rather than
  a throw:

  ```
  FATAL ERROR: v8::ToLocalChecked Empty MaybeLocal
  ```

  The redirect now checks the `MaybeLocal` and reports an ordinary error instead
  of aborting the process. Where V8 permits the redirect it still returns a
  working instance, so calling with or without `new` both behave as before on
  the runtimes where they already worked.

- **Process abort on garbage collection on Node 24.19 and newer.** Node 24.19.0
  added environment cleanup-hook calls to `node::ObjectWrap`, which this addon
  extended. An addon object's destructor runs from a V8 weak callback with no
  context entered, so `RemoveEnvironmentCleanupHook` hit Node's own
  `CHECK_NOT_NULL(env)` and aborted the whole process:

  ```
  node::RemoveEnvironmentCleanupHook ... Assertion failed: (env) != nullptr
  cryptian::AlgorithmStream<Arcfour>::~AlgorithmStream()
  ```

  It fired whenever a cipher or mode object was collected on an affected Node,
  so it struck ordinary programs that create and drop ciphers, and it was
  especially visible under test runners such as Vitest that collect aggressively.
  This is an upstream Node change that affected every `node::ObjectWrap` addon,
  not only this one. The addon now extends `Nan::ObjectWrap`, whose destructor
  resets its persistent handle and calls no cleanup hooks, so the null-context
  path cannot be reached. No API or output change.

### Note

- This does not change the separate `worker_threads` limitation: the addon is
  still registered with `NODE_MODULE` rather than the context-aware variant, so
  it cannot be loaded in a worker once the main thread has loaded it. That is
  tracked separately.

## v0.1.0

This release corrects several faults that changed output or could crash the
process. Some of the corrections change the bytes the library produces, so read
the compatibility note before upgrading.

### If you have data written by an earlier version

Two fixes change ciphertext for cases that were previously wrong:

- **Blowfish and CAST-128** encrypted incorrectly whenever the key contained a
  byte of `0x80` or higher, which is almost every real key. Data written by an
  affected version will not decrypt after upgrading, and it never interoperated
  with PHP mcrypt, OpenSSL, or anything else, because the output was wrong. The
  only recovery is to re-encrypt from the original source with a fixed version.

Everything else below either rejects input that used to be mishandled or fixes a
crash, so it does not change any output that was previously correct.

### Fixed

- **Blowfish and CAST-128 key schedules** sign-extended key bytes at or above
  `0x80`, corrupting the schedule. They now match libmcrypt for all keys.
- **Use-after-free**: a mode kept a raw pointer to its algorithm without keeping
  the algorithm's JavaScript object alive, so a construction like
  `new mode.cbc.Cipher(new algorithm.Rijndael128(), iv)` could crash the process
  once the algorithm was garbage collected. The mode now holds the algorithm for
  its own lifetime.
- **Initialization vector length** is now validated against the algorithm block
  size. A short vector previously caused an out-of-bounds read, and in CBC an
  out-of-bounds write, while appearing to succeed.
- **Stream initialization vectors**: `setIv` had an inverted comparison, so a new
  vector of the same length as the previous one was silently ignored. Arcfour
  additionally read past the end of the vector because of an operator precedence
  error in its index.
- **Raw `encrypt`/`decrypt`** on an algorithm now require exactly one block and
  throw otherwise. They previously either truncated multi-block input or, for
  Twofish and Serpent, returned a buffer whose trailing partial block was zeros.
  Empty input is a no-op.
- **Counted paddings** (`Pkcs5`, `Pkcs7`, `AnsiX923`, `Iso10126`) rejected a
  trailing length byte of zero and no longer accept a length past the end of the
  data. `Pkcs5` also verifies its final padding byte, which it previously skipped.
- **`BlockDecrypt` stream flush** reported a transform failure on the stream
  instead of throwing an uncaught exception.
- **`NotImplementedError`** now sets its own `name` and survives `instanceof`.

### Added

- **Twofish** (`MCRYPT_TWOFISH`), implemented from the specification and verified
  against published vectors and against libmcrypt.
- **Serpent** (`MCRYPT_SERPENT`), likewise.
- **Panama** (`MCRYPT_PANAMA`), verified against libmcrypt including its
  initialization-vector path.
- A migration guide, `docs/migrating-from-php-mcrypt.md`, mapping every mcrypt
  constant onto this library and covering the naming traps.
- Extensive test coverage: every cipher and mode is now checked against vectors
  generated from libmcrypt itself, the counted paddings against OpenSSL, and the
  remaining paddings and PCBC against their published definitions.

### Changed

- **Build** requires a C++20 toolchain, needed by the V8 headers in current Node
  releases. `engines` now declares Node 22 or newer, and CI covers Node 22, 24
  and 26 on Linux, macOS and Windows.
- The published package no longer contains the test suite, test vectors, or
  TypeScript sources, reducing it from 326 files to about 105.

### Notes

- `Threeway` requires `setEndianCompat(true)` to match mcrypt, since it defaults
  to the byte order of the original 3-Way. This was always the case but is now
  documented.
- The raw algorithm API processes a single block; use a mode for longer data.
- Modes are not context-aware and cannot be loaded in a `worker_threads` worker
  once the main thread has loaded the addon.
