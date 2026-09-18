# Managed-memory, numeric, and resource safety

Status: implemented; release verification pending
Last reviewed: 2026-09-13

Production application code uses Python 3.12+ and one small dependency-free JavaScript file. Both
runtimes manage string, object, and buffer memory without application pointer arithmetic, manual
allocation, or free operations. The repository contains no application C, C++, Rust, Cython, or
WebAssembly source, and runtime code cannot import direct native-memory interfaces such as
`ctypes`, `cffi`, `mmap`, shared memory, NumPy, or Numba.

Compiled third-party components such as the Python interpreter, cryptographic library, database
driver, and browser engine are consumed only through their memory-safe public APIs. Their versions
are locked, inventoried in the SBOM, scanned in the release images, and upgraded through the
documented release process; application code does not receive a pointer or native ownership
contract from them.

## Strings, buffers, and fixed-width values

Python strings and bytes are bounds-checked immutable values. The sole explicit `memoryview` is a
managed slice over an already serialized security-log byte string. Each successful `os.write`
replaces it with the remaining managed slice; no address or freed allocation is retained.

The only fixed-width binary conversions implement TOTP:

- `struct.pack(">Q", step)` serializes a non-negative Unix-time step to an explicit unsigned
  64-bit big-endian value; and
- `struct.unpack(">I", digest[offset:offset + 4])` reads an exactly four-byte HMAC slice, then masks
  the result to the 31-bit dynamic-truncation value required by TOTP.

The checker rejects native-size formats, dynamic format strings, any other `struct` site, shifts,
unreviewed buffer views, JavaScript `ArrayBuffer`/`DataView`/WebAssembly use, and unsafe memory
modules even when imported under an alias.

## Numeric overflow, sign, and range

Python integers use arbitrary precision, so application arithmetic does not wrap at machine-word
boundaries. Django and PostgreSQL provide the final signed database ranges. All 37 current
non-automatic integer fields are inventoried as bounded big-integer or positive integer types; a new
type or field changes the inventory and requires review.

Money and rates use `Decimal`, never binary floating-point input. The 38 stored decimal fields use
only two reviewed shapes: 18 digits with two decimal places for money and seven digits with four
decimal places for rates. Forms, import parsing, service normalization, model validation, and
database constraints enforce finiteness, scale, sign, and business ranges; rates are below 1000,
positive financial events cannot be zero, day/ordinal choices are bounded, uploads have byte/row/
column/cell limits, and projection horizons have explicit ceilings. Financial runtime modules are
forbidden from introducing `float()` conversion.

## Allocation and resource release

Managed objects are reclaimed by their runtimes and cannot become dangling application pointers.
External resources use bounded ownership:

- Django database connections, transactions, uploaded files, streaming responses, and framework
  request objects follow framework-managed lifetimes;
- both Unix datagram sockets and the one named temporary output use `with` blocks;
- every `os.fdopen` conversion is context-managed; and
- the six reviewed low-level descriptor files use explicit `try`/`finally` cleanup, close on
  validation failures, or transfer ownership into a context-managed file before clearing the raw
  descriptor sentinel.

The descriptor inventory pins each `os.open`, `os.fdopen`, and `os.close` count. A new low-level
resource site, an unmanaged socket or temporary file, or a changed cleanup shape fails review.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_managed_runtime_safety.py
.\.venv\Scripts\python.exe -m pytest tests\test_managed_runtime_safety.py tests\test_debt_projections.py tests\test_credit_card_calculations.py tests\test_security_log_archive.py
```

The checker scans all 219 production Python files and the production JavaScript asset, verifies the
38 decimal and 37 integer database fields, pins the managed buffer and fixed-width operations, and
tracks all six low-level descriptor files plus every context-managed socket and temporary file.
This implements ASVS `v5.0.0-1.4.1`, `v5.0.0-1.4.2`, and `v5.0.0-1.4.3` for application-owned code.
