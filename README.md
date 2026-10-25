# Phar Lap P3 EXP Loader for Ghidra

A Ghidra extension for importing Phar Lap P3 `.EXP` executables.

P3 is a flat-model 32-bit x86 protected-mode executable format used by Phar Lap
DOS extenders, including Free386. The loader keeps the addresses stored in the
file, including zero-based images, and uses the P3 header to recreate the image,
stack, heap, and segment layout in Ghidra.

## Supported format

- `P3` signature at file offset `0x00`
- Flat model field set to `1`
- 32-bit little-endian x86 image

Ghidra displays the loader as:

```text
Phar Lap P3 Executable (EXP)
```

The loader offers `x86:LE:32:default` with these compiler specs:

- `borlandcpp` preferred
- `default`
- `gcc`
- `windows`

## What it imports

- P3 header fields used for image layout, initial registers, heap and stack
  sizing, packed images, segment tables, symbols, and relocations
- Packed P3 images
- `DX` runtime parameter blocks
- Segment-based `.text`, `.data`, and `.rodata` blocks, using permissions from
  segment flags
- Flat images without segment tables, using `.flat_image` plus `.stack` and
  `.heap` when the header provides enough size information
- The parsed entry point as an `entry` label
- Initial `ESP`, `CS`, `SS`, `mindata`, and `maxdata` values as Program Info
  properties

## Build

For Ghidra 12.2, set `JAVA_HOME` to JDK 25 and use the included Gradle 9.1.0 wrapper.

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation:

```bash
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra ./gradlew clean build
```

Build the installable extension zip with:

```bash
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra ./gradlew distributeExtension
```

The extension zip is written to `dist/`.

## Install

1. Build the extension zip with the same Ghidra version you plan to run.
2. In Ghidra, open `File > Install Extensions...`.
3. Select the generated zip and restart Ghidra if prompted.
4. Import a P3 `.EXP` file and choose `Phar Lap P3 Executable (EXP)`.

Prefer the Borland C++ compiler spec unless the executable is known to come
from another toolchain.

## Current scope

- Relocation tables are reported but not applied.
- Symbol tables are reported but not imported.
- Header checksums are reported but not validated.
- Segment table parsing may need adjustment for uncommon P3 variants.

## License

This project is licensed under the GNU General Public License v3.0. The Gradle
wrapper and Ghidra-provided build template retain their upstream license
notices.
