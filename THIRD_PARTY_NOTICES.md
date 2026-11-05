# Third-party provenance and notices

Original Otherwise Protocol code and documentation are Apache-2.0 (see LICENSE and NOTICE). Dependencies, their vendored components and the base operating system retain their own licences. Nothing here relicenses those works.

## Python inputs

All runtime, build and schema-test packages are versioned and wheel-hash-locked. The version-specific public PyPI metadata and wheel download URLs/hashes are in [the provenance manifest](build/python-provenance.json). Licence files were copied from the installed, hash-verified distributions; their hashes and local paths are recorded in that manifest.

| Package | Version | Declared licence | Role |
|---|---|---|---|
| [attrs](https://pypi.org/project/attrs/26.1.0/) | 26.1.0 | MIT | schema tests |
| [cffi](https://pypi.org/project/cffi/2.1.1/) | 2.1.1 | MIT-0 | runtime |
| [cryptography](https://pypi.org/project/cryptography/46.0.3/) | 46.0.3 | Apache-2.0 OR BSD-3-Clause | runtime |
| [jsonschema](https://pypi.org/project/jsonschema/4.25.1/) | 4.25.1 | MIT | schema tests |
| [jsonschema-specifications](https://pypi.org/project/jsonschema-specifications/2025.9.1/) | 2025.9.1 | MIT | schema tests |
| [pycparser](https://pypi.org/project/pycparser/3.12/) | 3.12 | BSD-3-Clause | runtime |
| [pynacl](https://pypi.org/project/pynacl/1.6.2/) | 1.6.2 | Apache-2.0; bundled Sodium notice | runtime |
| [referencing](https://pypi.org/project/referencing/0.37.0/) | 0.37.0 | MIT | schema tests |
| [rpds-py](https://pypi.org/project/rpds-py/2026.9.1/) | 2026.9.1 | MIT | schema tests |
| [setuptools](https://pypi.org/project/setuptools/80.9.0/) | 80.9.0 | MIT | build |
| [typing-extensions](https://pypi.org/project/typing-extensions/4.16.0/) | 4.16.0 | PSF-2.0 | schema tests |
| [wheel](https://pypi.org/project/wheel/0.45.1/) | 0.45.1 | MIT; bundled notices | build |

The retained files under [third_party/python](third_party/python) include vendored-component notices where supplied; the main-package licence label is not a blanket licence for every bundled component. No third-party Python source or wheel is vendored into the repository. Generated Python wheels contain the original reference package, not its dependency binaries.

## Native runtime and images

Pinned public Docker Official Image digests are specified in Dockerfile and Dockerfile.php. Exact Debian package URLs and SHA-256 values are in build/debian/arm64.lock and build/debian/amd64.lock. These locks were resolved and downloaded using signed Debian APT metadata; subsequent builds use apt-helper with the committed SHA-256, not a floating package index. The package URLs use public HTTP mirrors, with integrity supplied by the committed hashes.

[Debian provenance](build/debian-provenance.json) records the tested native package versions and hashes of the retained public copyright inventories in [third_party/debian](third_party/debian). Full package notices also remain under /usr/share/doc inside built containers. PHP 8.2 uses PHP License 3.01 and includes other component notices; Sodium uses ISC, OpenSSL 3 uses Apache-2.0, and libffi has its supplied permissive notice. Consult the retained files for their exact scope.

This product includes PHP software, freely available from <https://www.php.net/software/>. This acknowledgement is not an endorsement.

Python/PHP implement protocol logic independently but share the Sodium family. Python cryptography wheels bundle their own OpenSSL; PHP links the locked Debian OpenSSL. No claim of independent cryptographic-library review follows.

## Sources and review scope

Licence verification uses the actual distribution notices, version-specific PyPI records, Debian copyright inventories, the [Apache licence text](https://www.apache.org/licenses/LICENSE-2.0.txt), and the [PHP 3.01 text](https://www.php.net/license/3_01.txt). Public author attributions/contact details required by supplied third-party notices are intentionally retained and are distinct from private developer information.

This is a provenance/licence inventory, not a legal opinion or a vulnerability assessment of every dependency. Software distribution and rebuilding still require upstream artifact availability; see [Building](docs/BUILDING.md).
