# Changelog

## Unreleased

### Added
- Clear `LibraryLoadError` (an `ImportError`) when `libopencie-pkcs11` cannot
  be loaded, naming the library, the `OPENCIE_PKCS11_LIB` override and the
  releases page.
- Import-time version check: libopencie-pkcs11 >= 1.3.0 is required
  (probed through `cie_read_dgs_can` / `cie_last_error`).
- `py.typed` marker, PyPI metadata (readme, authors, license files, URLs),
  `dev` extra.
- Release workflow publishing to PyPI via trusted publishing (tag `v*`) and to
  TestPyPI (manual dispatch).

### Changed
- Libraries older than 1.3.0 are now rejected at import instead of failing
  per call with `AttributeError`.
