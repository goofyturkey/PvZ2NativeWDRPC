#!/usr/bin/env python3
"""Print a libPVZ2.so's per-version facts, and a kVersions entry to paste.

This is the offline twin of pvz2native/src/game/build_scan.cpp. At runtime that
scanner finds an unknown build's natives by reading its RegisterNatives tables
out of the loaded image; this script does the same against the file on disk, so
a build can be mapped without running the game at all:

    python3 tools/dump_jni_tables.py GT_30FPS.apk
    python3 tools/dump_jni_tables.py libPVZ2.so --json

It accepts an APK/XAPK/ZIP (the arm32 libPVZ2.so is found inside) or the .so
itself, applies the ELF relocations the way the loader does at base 0, and then:

  * lists every {name, signature, function} triple it can validate, with the
    offset of each native this port calls;
  * prints the two 8-byte fingerprints game_symbols_detect() compares;
  * parses Native_GameAppInitialize's declared objects out of its signature;
  * infers the onSurfaceChanged argument padding from the body's first MOVs;
  * emits a ready-to-paste entry for kVersions in src/game/symbols.cpp, with
    the fields it CANNOT recover called out (globals, field offsets, patch
    sites -- those need a disassembler and a human).

What is left unmapped is not a bug in this script: nothing in the image names
`&LawnApp`, `Board::mBoardState` or an inline `BL` to the purchase broker.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile
from dataclasses import dataclass, field

EM_ARM = 40
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4

DT_NULL = 0
DT_STRTAB = 5
DT_SYMTAB = 6
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_JMPREL = 23
DT_PLTRELSZ = 2

R_ARM_ABS32 = 2
R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23

# Names and the signatures the Java side declares (classesdex/). The signature
# check is what lets a lone triple be trusted: it keeps a name string that
# happens to sit beside some other method's signature out of the map.
NATIVES = {
    "Native_GameAppInitialize": "(L*",  # prefix: the object list itself is parsed below
    "Native_applicationWillFinishLaunching": "(Ljava/lang/String;)V",
    "Native_applicationDidFinishLaunching": "()V",
    "Native_applicationWillBecomeForeground": "()V",
    "Native_applicationDidBecomeActive": "()V",
    "Native_onSurfaceCreated": "()V",
    "Native_onSurfaceChanged": "(II)V",
    "Native_onDrawFrame": "()V",
    # 9.6.1 registers this one WITHOUT the Native_ prefix, and everything
    # derived from it (Reflourished, Grind Thousand) keeps that spelling.
    "PumpMessageQueue": "()V",
    "Native_PumpMessageQueue": "()V",  # only if some build prefixes it
    "Native_createNativeApplicationLifecycleObserver": None,
    "Native_NotifySurfaceChange": "(Z)V",
    "Native_NotifyAppRunning": "(Z)V",
    "Native_NotifyFocusChange": "(Z)V",
    "HttpReceivedResponse": "(J)V",
    "HttpReceivedData": "(J[BI)V",
    "HttpTransactionComplete": "(J)V",
    "HttpTransactionError": "(J)V",
}

# Field names in GameSymbols::native / jni_native, in the order the table prints
# them, so the pasted entry reads like the ones already in symbols.cpp.
FIELD_OF = {
    "Native_GameAppInitialize": ("native", "game_app_initialize"),
    "Native_applicationWillFinishLaunching": ("native", "application_will_finish_launching"),
    "Native_applicationDidFinishLaunching": ("native", "application_did_finish_launching"),
    "Native_applicationWillBecomeForeground": ("native", "application_will_become_foreground"),
    "Native_applicationDidBecomeActive": ("native", "application_did_become_active"),
    "Native_onSurfaceCreated": ("native", "on_surface_created"),
    "Native_onSurfaceChanged": ("native", "on_surface_changed"),
    "Native_onDrawFrame": ("native", "on_draw_frame"),
    "PumpMessageQueue": ("native", "pump_message_queue"),
    "Native_PumpMessageQueue": ("native", "pump_message_queue"),
    "Native_createNativeApplicationLifecycleObserver": ("native", "create_lifecycle_observer"),
    "Native_NotifySurfaceChange": ("native", "notify_surface_change"),
    "Native_NotifyAppRunning": ("native", "notify_app_running"),
    "Native_NotifyFocusChange": ("native", "notify_focus_change"),
    "HttpReceivedResponse": ("jni_native", "http_received_response"),
    "HttpReceivedData": ("jni_native", "http_received_data"),
    "HttpTransactionComplete": ("jni_native", "http_transaction_complete"),
    "HttpTransactionError": ("jni_native", "http_transaction_error"),
}

REQUIRED = (
    "Native_GameAppInitialize",
    "Native_applicationWillFinishLaunching",
    "Native_applicationDidFinishLaunching",
    "Native_applicationWillBecomeForeground",
    "Native_applicationDidBecomeActive",
    "Native_onSurfaceCreated",
    "Native_onSurfaceChanged",
    "Native_onDrawFrame",
)

# The object lists symbols.cpp already has; a signature that parses to one of
# these counts can reuse the array instead of declaring a new one.
LEGACY_OBJECTS = 8
MODERN_OBJECTS = 7


class NotAnArm32Elf(Exception):
    pass


@dataclass
class Segment:
    vaddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass
class Image:
    data: bytearray
    segments: list[Segment]

    def readable(self, va: int, n: int) -> bool:
        return 0 <= va and va + n <= len(self.data)

    def u32(self, va: int) -> int:
        return struct.unpack_from("<I", self.data, va)[0]

    def u64(self, va: int) -> int:
        return struct.unpack_from("<Q", self.data, va)[0]

    def cstr(self, va: int, limit: int) -> bytes | None:
        if not self.readable(va, 1):
            return None
        end = self.data.find(b"\x00", va, min(va + limit, len(self.data)))
        if end < 0:
            return None
        return bytes(self.data[va:end])

    def in_exec(self, va: int) -> bool:
        return any(s.flags & PF_X and s.vaddr <= va < s.vaddr + s.memsz for s in self.segments)

    def in_write(self, va: int) -> bool:
        return any(s.flags & PF_W and s.vaddr <= va < s.vaddr + s.memsz for s in self.segments)


def load_elf(raw: bytes, name: str) -> Image:
    if len(raw) < 52 or raw[:4] != b"\x7fELF":
        raise NotAnArm32Elf(f"{name}: not an ELF file")
    if raw[4] != 1:
        raise NotAnArm32Elf(f"{name}: not ELF32 (this port needs armeabi-v7a)")
    if raw[5] != 1:
        raise NotAnArm32Elf(f"{name}: not little-endian")
    (e_type, e_machine, _ver, _entry, e_phoff, _shoff, _flags, _ehsize, e_phentsize,
     e_phnum, _shentsize, _shnum, _shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", raw, 16)
    if e_machine != EM_ARM:
        raise NotAnArm32Elf(f"{name}: e_machine {e_machine}, not ARM ({EM_ARM})")
    if e_phnum == 0:
        raise NotAnArm32Elf(f"{name}: no program headers")

    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = \
            struct.unpack_from("<IIIIIIII", raw, off)
        phdrs.append((p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags))

    loads = [p for p in phdrs if p[0] == PT_LOAD]
    if not loads:
        raise NotAnArm32Elf(f"{name}: no PT_LOAD segments")
    span = max(p[2] + p[4] for p in loads)

    data = bytearray(span)
    segments = []
    for _t, p_offset, p_vaddr, p_filesz, p_memsz, p_flags in loads:
        chunk = raw[p_offset:p_offset + p_filesz]
        data[p_vaddr:p_vaddr + len(chunk)] = chunk
        segments.append(Segment(p_vaddr, p_filesz, p_memsz, p_flags))

    image = Image(data, segments)

    # Dynamic section. Reading it after the segments are in place is what the
    # loader does too, and it means DT_REL/DT_SYMTAB are ordinary vaddrs here.
    dyn = None
    for p_type, p_offset, p_vaddr, p_filesz, _memsz, _flags in phdrs:
        if p_type == PT_DYNAMIC:
            dyn = (p_vaddr, p_filesz)
            break
    if dyn is None:
        return image  # static-looking object: table words are already final

    tags: dict[int, int] = {}
    va, size = dyn
    for i in range(0, size, 8):
        if not image.readable(va + i, 8):
            break
        tag, val = struct.unpack_from("<II", image.data, va + i)
        if tag == DT_NULL:
            break
        tags.setdefault(tag, val)

    def sym_value(index: int) -> int:
        symtab = tags.get(DT_SYMTAB)
        if symtab is None or index == 0:
            return 0
        return struct.unpack_from("<I", image.data, symtab + index * 16 + 4)[0]

    def apply(rel_vaddr: int, rel_size: int) -> None:
        if not rel_vaddr or not rel_size:
            return
        for off in range(0, rel_size, 8):
            r_offset, r_info = struct.unpack_from("<II", image.data, rel_vaddr + off)
            r_type = r_info & 0xFF
            r_sym = r_info >> 8
            if not image.readable(r_offset, 4):
                continue
            place = image.u32(r_offset)
            if r_type == R_ARM_RELATIVE:
                # The addend is already in place and the load bias is 0.
                continue
            if r_type == R_ARM_ABS32:
                struct.pack_into("<I", image.data, r_offset, (place + sym_value(r_sym)) & 0xFFFFFFFF)
            elif r_type in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT):
                struct.pack_into("<I", image.data, r_offset, sym_value(r_sym) & 0xFFFFFFFF)

    apply(tags.get(DT_REL, 0), tags.get(DT_RELSZ, 0))
    apply(tags.get(DT_JMPREL, 0), tags.get(DT_PLTRELSZ, 0))
    return image


@dataclass
class Triple:
    at: int
    name: str
    signature: str
    fn: int
    known: bool


@dataclass
class Report:
    source: str
    module: str
    size: int
    triples: list[Triple] = field(default_factory=list)
    mapped: dict[str, int] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    game_app_args: list[str] = field(default_factory=list)
    surface_pad: int = 1
    pad_assumed: bool = True
    fingerprints: dict[str, int] = field(default_factory=dict)


def plausible_code(image: Image, va: int) -> bool:
    if va == 0 or not image.readable(va, 4):
        return False
    insn = image.u32(va)
    return insn != 0 and (insn & 0xF0000000) != 0xF0000000


def signature_fits(name: str, signature: str) -> bool:
    want = NATIVES.get(name)
    if want is None:
        return True  # createNativeApplicationLifecycleObserver: not recorded
    if want.endswith("*"):
        return signature.startswith(want[:-1])
    return signature == want


def scan(image: Image) -> Report:
    report = Report(source="", module="", size=len(image.data))
    data = image.data
    for at in range(0, len(data) - 12 + 1, 4):
        name_ptr = image.u32(at)
        # Cheap filter first: a real image is 20-30 MB, so this loop runs
        # millions of times and a full cstring scan per word would dominate.
        if not image.readable(name_ptr, 8):
            continue
        head = data[name_ptr:name_ptr + 8]
        # Every native name starts with an upper-case letter. Deliberately not
        # filtered on a "Native_" prefix: 9.6.1 registers PumpMessageQueue bare,
        # and that is the one native whose absence leaves a 9.x boot painting
        # nothing.
        if not head[:1].isupper():
            continue
        raw_name = image.cstr(name_ptr, 96)
        if raw_name is None:
            continue
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not all(c.isalnum() or c in "_$" for c in name):
            continue
        raw_sig = image.cstr(image.u32(at + 4), 1024)
        if raw_sig is None or not raw_sig.startswith(b"(") or b")" not in raw_sig:
            continue
        # A JNI signature is a restricted alphabet; a printf format like
        # "(%d x %d)" has the same shape and is not one.
        if not all(chr(c).isalnum() or c in b"()[];/_$" for c in raw_sig):
            continue
        try:
            signature = raw_sig.decode("ascii")
        except UnicodeDecodeError:
            continue
        fn = image.u32(at + 8)
        if fn & 3:
            continue  # ARM code is word-aligned; an odd "function" is a datum
        if not image.readable(fn, 4) or not plausible_code(image, fn):
            continue
        if not image.in_exec(fn):
            continue
        report.triples.append(Triple(at, name, signature, fn, name in NATIVES))

    for t in report.triples:
        if not t.known or t.name in report.mapped:
            continue
        if not signature_fits(t.name, t.signature):
            continue
        report.mapped[t.name] = t.fn

    report.missing = [n for n in REQUIRED if n not in report.mapped]

    game_app = next((t for t in report.triples if t.name == "Native_GameAppInitialize"), None)
    if game_app is not None:
        report.game_app_args = parse_args(game_app.signature)

    pad_target = report.mapped.get("Native_onSurfaceChanged")
    if pad_target is not None:
        report.surface_pad, report.pad_assumed = infer_pad(image, pad_target)

    for key, native in (("draw_frame", "Native_onDrawFrame"),
                        ("game_app_init", "Native_GameAppInitialize")):
        fn = report.mapped.get(native)
        if fn is not None and image.readable(fn, 8):
            report.fingerprints[key] = image.u64(fn)
    return report


def parse_args(signature: str) -> list[str]:
    args = []
    i = 1
    while i < len(signature) and signature[i] != ")":
        if signature[i] == "L":
            semi = signature.find(";", i)
            if semi < 0:
                return []
            args.append(signature[i:semi])
            i = semi + 1
        elif signature[i] == "[":
            return []
        else:
            i += 1
    return args


def infer_pad(image: Image, fn: int) -> tuple[int, bool]:
    seen = set()
    for i in range(16):
        if not image.readable(fn + i * 4, 4):
            break
        word = image.u32(fn + i * 4)
        if (word & 0x0FEF0000) != 0x01A00000:  # MOV Rd, Rm
            continue
        seen.add(word & 0xF)
    if {3, 4} <= seen:
        return 2, False
    if {2, 3} <= seen:
        return 1, False
    if {1, 2} <= seen:
        return 0, False
    return 1, True


def find_module(path: str) -> tuple[bytes, str]:
    if not zipfile.is_zipfile(path):
        with open(path, "rb") as fh:
            return fh.read(), path.rsplit("/", 1)[-1]

    with zipfile.ZipFile(path) as zf:
        candidates = [n for n in zf.namelist() if n.lower().endswith("libpvz2.so")]
        if not candidates:
            raise NotAnArm32Elf(f"{path}: no libPVZ2.so inside")

        def rank(n: str) -> tuple[int, str]:
            low = n.lower()
            # armeabi-v7a first; an arm64 or x86 copy cannot run here.
            if "arm64" in low or "aarch64" in low:
                return (1, n)
            if "x86" in low or "x64" in low:
                return (2, n)
            return (0, n)

        chosen = sorted(candidates, key=rank)[0]
        return zf.read(chosen), chosen


def fmt_entry(report: Report) -> str:
    lines = []
    lines.append("    /* --- <put the version string here> (armeabi-v7a) -------------")
    lines.append("     *")
    lines.append(f"     * {report.module}, {report.size / (1024 * 1024):.1f} MB image.")
    if report.missing:
        lines.append(f"     * REQUIRED NATIVES MISSING: {', '.join(report.missing)}")
        lines.append("     *   -> this build does not match the engine generation this port drives.")
    if report.surface_pad is not None and report.pad_assumed:
        lines.append("     * surface_changed_pad is the default 1: no MOV evidence in onSurfaceChanged.")
    lines.append("     * patch/probe/input are not recoverable from the image -- see the tail of")
    lines.append("     * this script's output. */")
    lines.append("    {")
    lines.append('        .version = "<version>",')
    lines.append("        .native = {")
    order = [(n, FIELD_OF[n]) for n in FIELD_OF if n in report.mapped]
    for name, (group, field_name) in order:
        lines.append(f"            .{field_name:<34} = 0x{report.mapped[name]:x}, /* {name} */")
    lines.append("        },")
    lines.append(f"        .surface_changed_pad = {report.surface_pad},")
    if "draw_frame" in report.fingerprints:
        lines.append(f"        .fingerprint_draw_frame    = 0x{report.fingerprints['draw_frame']:016X}ull,")
    if "game_app_init" in report.fingerprints:
        lines.append(f"        .fingerprint_game_app_init = 0x{report.fingerprints['game_app_init']:016X}ull,")
    if report.game_app_args:
        count = len(report.game_app_args)
        if count == MODERN_OBJECTS:
            lines.append("        .game_app_init_args      = kGameAppInitArgs961,")
            lines.append("        .game_app_init_arg_count = kCount(kGameAppInitArgs961),")
        elif count == LEGACY_OBJECTS:
            lines.append("        .game_app_init_args      = kGameAppInitArgsLegacy,")
            lines.append("        .game_app_init_arg_count = kCount(kGameAppInitArgsLegacy),")
        else:
            lines.append(f"        /* GameAppInitialize declares {count} objects -- no built-in array")
            lines.append("         * matches, so add one for this build: */")
            for i, arg in enumerate(report.game_app_args):
                lines.append(f"        /*   [{i}] {arg} */")
    lines.append("    },")
    return "\n".join(lines)


def print_human(report: Report) -> None:
    print(f"module      : {report.module}")
    print(f"image span  : 0x{report.size:x} ({report.size / (1024 * 1024):.1f} MB)")
    print(f"triples     : {len(report.triples)} validated, {sum(1 for t in report.triples if t.known)} known")
    print()
    print("natives this port calls")
    for name in FIELD_OF:
        if name in report.mapped:
            group, field_name = FIELD_OF[name]
            print(f"  {name:<52} 0x{report.mapped[name]:08x}  {group}.{field_name}")
    unused = [t for t in report.triples if not t.known]
    if unused:
        print()
        print("other registered natives (not used by this port)")
        for t in unused:
            print(f"  {t.name:<52} 0x{t.fn:08x}  {t.signature}")
    print()
    if report.missing:
        print("MISSING REQUIRED NATIVES: " + ", ".join(report.missing))
        print("  A build without these is not one this port can boot.")
    else:
        print("all required natives found")
    print()
    print("Native_GameAppInitialize objects")
    for i, arg in enumerate(report.game_app_args):
        print(f"  [{i}] {arg}")
    print()
    pad_note = " (assumed: no MOV evidence)" if report.pad_assumed else ""
    print(f"onSurfaceChanged pad : {report.surface_pad}{pad_note}")
    print()
    print("fingerprints")
    print(f"  onDrawFrame       0x{report.fingerprints.get('draw_frame', 0):016X}")
    print(f"  GameAppInitialize 0x{report.fingerprints.get('game_app_init', 0):016X}")
    print()
    print("kVersions entry")
    print(fmt_entry(report))
    print()
    print("Still to map by hand (nothing in the image names them):")
    print("  global.app / global.app_driver, lawn_app_got / gsm_got / world_map_slot,")
    print("  lawn_app_board / board_state / board_pause_sources / board_level_num,")
    print("  fn.string_ctor, every `patch` offset, and the `probe`/`input` fields.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="APK/XAPK/ZIP containing an arm32 libPVZ2.so, or the .so itself")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        raw, module = find_module(args.path)
        image = load_elf(raw, module)
    except (OSError, NotAnArm32Elf) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = scan(image)
    report.source = args.path
    report.module = module

    if args.json:
        print(json.dumps({
            "source": report.source,
            "module": report.module,
            "size": report.size,
            "natives": report.mapped,
            "missing": report.missing,
            "game_app_args": report.game_app_args,
            "surface_changed_pad": report.surface_pad,
            "surface_changed_pad_assumed": report.pad_assumed,
            "fingerprints": {k: f"0x{v:016x}" for k, v in report.fingerprints.items()},
            "other_natives": [{"name": t.name, "signature": t.signature, "offset": f"0x{t.fn:x}"}
                              for t in report.triples if not t.known],
            "entry": fmt_entry(report),
        }, indent=2))
        return 0

    print_human(report)
    return 0 if not report.missing else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
