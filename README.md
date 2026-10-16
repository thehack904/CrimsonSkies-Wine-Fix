# Crimson Skies (2000) — `roffile.dll` Preferences / Quit Mission crash workaround

**Status:** Functional workaround confirmed on one tested `roffile.dll` build under GE-Proton 11-9 / UMU Steam Runtime 4, Kubuntu 26.04.1, and Intel HD 4000. Not a universal fix or a Wine upstream patch.

**Related WineHQ report:** [Bug #34774 — Crimson Skies crashes when a mission ends](https://bugs.winehq.org/show_bug.cgi?id=34774).

## Symptoms

In the original PC version of *Crimson Skies* (2000), entering **Preferences** while in a mission or choosing **Quit Mission** can crash instead of navigating to the intended screen. A debugger recorded a SIGSEGV in `roffile.dll` at RVA `0x22E0`, dereferencing `ESI` on the first unmapped page (`0x07BF0000` in the tested run).

## Investigation

- `crimson.rof` contains an indexed, zlib-compressed `LAYOUT.CSV`. The recovered stream begins at archive offset `0x91EF`, consumes **15,078 bytes**, and expands to **56,148 bytes**. It decompresses cleanly and ends in CRLF, not NUL.
- The game's process contained an exact 56,148-byte copy of that layout beginning at `0x07BE0728`, ending at `0x07BEE27C`.
- A GDB parser-entry trace showed the cursor begin at `0x07BE0728`, advance through the layout, and continue beyond its end into unrelated memory. Earlier fault registers showed a cursor at `0x07BEFFDB` and a fault at `0x07BF0000`.
- The parser's instruction sequence near RVA `0x231E` is:

  ```asm
  cmp byte ptr [esi], 0x20
  jge  short keep_cursor
  inc esi                   ; original byte 0x46
  keep_cursor:
  mov [edi], esi
  ```

  In this control path, NUL (`0x00`) is below `0x20`, so the parser advances past it. On its next invocation, the routine can treat bytes after the terminator as further input, ultimately reaching inaccessible memory. This explains the trace. It is not yet proven whether changing this instruction has other consequences in every game version.

## One-byte workaround

For the **exact DLL build** whose SHA-256 is:

```
1bc7b4b1adba1bf6a510e62f93473824c662acbf2a2176087b7b4b85338ba58a
```

replace `INC ESI` (`0x46`) with `NOP` (`0x90`) at **RVA `0x231E`**. This is a one-byte change. The expected surrounding bytes are:

```
original: 80 3e 20 7d 01 46 89 37
patched:  80 3e 20 7d 01 90 89 37
```

**Do not use RVA as a raw file offset.** The included utility parses PE section headers to find the file offset. It also refuses unknown DLL builds and preserves an original backup. It does **not** download or redistribute the game or Microsoft DLL.

### Usage

Exit the game before changing the DLL. Make a separate copy of your installation for initial testing.

```bash
python3 crimson-skies-rof-nul-guard.py status --dll '/path/to/Crimson Skies/GOSDATA/ASSETS/BINARIES/roffile.dll'
python3 crimson-skies-rof-nul-guard.py apply --dll '/path/to/Crimson Skies/GOSDATA/ASSETS/BINARIES/roffile.dll'
```

To restore the original DLL (exit the game first):

```bash
python3 crimson-skies-rof-nul-guard.py restore --dll '/path/to/Crimson Skies/GOSDATA/ASSETS/BINARIES/roffile.dll'
```

After patching, test Preferences, Quit Mission, returning to Main Menu, starting another mission, saving/loading, and a cold restart. A successful patch of the exact DLL does **not** guarantee success on other builds, systems, or configurations.

## Verified in the initial test

The tester completed: enter Preferences; return to mission; Quit Mission; return to the main menu; start and exit another mission; change settings; save/load; exit game to desktop; and repeat after restarting the game. All passed in the isolated patched installation.

**Test environment:** HP Elite 8300 USDT, Intel HD 4000, Kubuntu 26.04.1, GE-Proton 11-9 via Lutris/UMU Steam Runtime 4. No claim is made that these components are required for this particular parser fix.

## Scope and limitations

- This is a narrowly scoped **game DLL binary patch**, not a Wine/Proton graphics, Vulkan, or system-wide setting.
- No testing across other `roffile.dll` SHA-256 versions has been completed.
- The root cause is strongly supported by the parser trace and an A/B patch result; extensive compatibility testing remains worthwhile.
- Users should retain backups and avoid sharing proprietary DLL files.
