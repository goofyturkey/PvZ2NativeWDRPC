#!/usr/bin/env python3
"""Self-test for tools/dump_jni_tables.py.

It builds a tiny ARM32 shared object with the same shape as the real thing -- a
read+execute segment holding strings and function bodies, a read+write segment
holding JNINativeMethod arrays, a .dynamic that describes .rel.dyn -- and checks
that the tool reads it the way the loader would: absolute pointers resolved,
signatures matched, padding inferred, fingerprints taken.

Run:  python3 tools/test_dump_jni_tables.py
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "dump_jni_tables.py")

TEXT_VADDR = 0x1000
TEXT_SIZE = 0x1000
DATA_VADDR = 0x2000
DATA_SIZE = 0x1000

SIG7 = ("(Lcom/popcap/SexyAppFramework/AndroidSurfaceView;"
        "Lcom/popcap/SexyAppFramework/AndroidHttpProxy;"
        "Lcom/popcap/SexyAppFramework/cloud/Cloud;"
        "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayConnect;"
        "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayAchievements;"
        "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayLeaderboard;"
        "Lcom/popcap/SexyAppFramework/AndroidNotification;)Z")

REQUIRED = [
    ("Native_GameAppInitialize", SIG7),
    ("Native_applicationWillFinishLaunching", "(Ljava/lang/String;)V"),
    ("Native_applicationDidFinishLaunching", "()V"),
    ("Native_applicationWillBecomeForeground", "()V"),
    ("Native_applicationDidBecomeActive", "()V"),
    ("Native_onSurfaceCreated", "()V"),
    ("Native_onSurfaceChanged", "(II)V"),
    ("Native_onDrawFrame", "()V"),
]

PUSH_R4_LR = 0xE92D4010
BX_LR = 0xE12FFF1E
MOV_R5_R2 = 0xE1A05002
MOV_R4_R3 = 0xE1A04003


class Builder:
    def __init__(self) -> None:
        self.image = bytearray(DATA_VADDR + DATA_SIZE)
        self.next_string = TEXT_VADDR + 0x100
        self.next_fn = TEXT_VADDR + 0x400
        self.next_entry = DATA_VADDR + 0x040
        self.symbols: list[int] = []  # st_value per dynsym index (index 0 is null)
        self.relocs: list[tuple[int, int, int]] = []  # (r_offset, r_type, sym_index)

    def put32(self, va: int, value: int) -> None:
        struct.pack_into("<I", self.image, va, value & 0xFFFFFFFF)

    def string(self, text: str) -> int:
        raw = text.encode() + b"\x00"
        at = self.next_string
        self.image[at:at + len(raw)] = raw
        self.next_string += len(raw)
        self.next_string = (self.next_string + 3) & ~3
        return at

    def function(self, movs: tuple[int, ...] = ()) -> int:
        at = self.next_fn
        words = [PUSH_R4_LR, *movs, BX_LR]
        for i, word in enumerate(words):
            self.put32(at + i * 4, word)
        self.next_fn += 0x40
        return at

    def entry(self, name: str, signature: str, fn: int, via_symbol: bool = False) -> None:
        at = self.next_entry
        self.put32(at, self.string(name))
        self.put32(at + 4, self.string(signature))
        if via_symbol:
            # What a linker emits for an absolute reference to a local symbol:
            # an R_ARM_ABS32 whose resolved value comes from .dynsym, not from
            # the word in the file. The tool must apply it, not read the zero.
            self.put32(at + 8, 0)
            self.symbols.append(fn)
            self.relocs.append((at + 8, 2, len(self.symbols)))
        else:
            self.put32(at + 8, fn)
        self.next_entry += 12

    def build(self) -> bytes:
        dynsym_at = DATA_VADDR + 0x400
        dynstr_at = DATA_VADDR + 0x500
        rel_at = DATA_VADDR + 0x600
        dynamic_at = DATA_VADDR + 0x800

        self.image[dynstr_at] = 0
        for i, value in enumerate(self.symbols, start=1):
            struct.pack_into("<IIIBBH", self.image, dynsym_at + i * 16,
                             0, value, 0, 0x12, 0, 1)
        for i, (offset, r_type, sym) in enumerate(self.relocs):
            struct.pack_into("<II", self.image, rel_at + i * 8, offset, (sym << 8) | r_type)

        dynamic = [
            (17, rel_at),                      # DT_REL
            (18, len(self.relocs) * 8),        # DT_RELSZ
            (6, dynsym_at),                    # DT_SYMTAB
            (11, 16),                          # DT_SYMENT
            (5, dynstr_at),                    # DT_STRTAB
            (0, 0),                            # DT_NULL
        ]
        for i, (tag, val) in enumerate(dynamic):
            struct.pack_into("<II", self.image, dynamic_at + i * 8, tag, val)

        phdrs = [
            (1, TEXT_VADDR, TEXT_VADDR, TEXT_SIZE, TEXT_SIZE, 5),                 # LOAD R+X
            (1, DATA_VADDR, DATA_VADDR, DATA_SIZE, DATA_SIZE, 6),                 # LOAD R+W
            (2, DATA_VADDR, dynamic_at, len(dynamic) * 8, len(dynamic) * 8, 6),   # DYNAMIC
        ]

        header = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
        header += struct.pack("<HHIIIIIHHHHHH",
                              3,          # e_type = ET_DYN
                              40,         # e_machine = EM_ARM
                              1,          # e_version
                              0,          # e_entry
                              52,         # e_phoff
                              0,          # e_shoff
                              0x05000000, # e_flags (EABI5)
                              52,         # e_ehsize
                              32,         # e_phentsize
                              len(phdrs), # e_phnum
                              0, 0, 0)

        phdr_bytes = b"".join(struct.pack("<IIIIIIII", p[0], p[1], p[2], p[2], p[3], p[4], p[5], 4)
                              for p in phdrs)
        head = header + phdr_bytes
        if len(head) > TEXT_VADDR:
            raise AssertionError("header does not fit before the text segment")
        # File offsets equal vaddrs, which keeps the fixture readable: the
        # header lives below the text segment and everything else is copied
        # straight across.
        blob = bytearray(len(self.image))
        blob[:len(head)] = head
        blob[TEXT_VADDR:] = self.image[TEXT_VADDR:]
        return bytes(blob)


def make_image() -> bytes:
    b = Builder()
    for i, (name, sig) in enumerate(REQUIRED):
        movs = (MOV_R5_R2, MOV_R4_R3) if name == "Native_onSurfaceChanged" else ()
        # Half the entries go through a relocation, so the resolver is exercised.
        b.entry(name, sig, b.function(movs), via_symbol=(i % 2 == 0))
    b.entry("Native_PumpMessageQueue", "()V", b.function())
    b.entry("Native_DoSomethingElse", "(I)I", b.function())
    return b.build()


class ToolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.so_path = os.path.join(cls.tmp.name, "libPVZ2.so")
        with open(cls.so_path, "wb") as fh:
            fh.write(make_image())
        cls.run_result = subprocess.run([sys.executable, TOOL, cls.so_path],
                                        capture_output=True, text=True, check=False)
        cls.json_result = subprocess.run([sys.executable, TOOL, cls.so_path, "--json"],
                                         capture_output=True, text=True, check=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_exit_code_is_clean(self) -> None:
        self.assertEqual(self.run_result.returncode, 0, self.run_result.stderr)
        self.assertEqual(self.json_result.returncode, 0, self.json_result.stderr)

    def test_natives_are_found(self) -> None:
        data = json.loads(self.json_result.stdout)
        self.assertEqual(data["missing"], [])
        natives = data["natives"]
        for name, _sig in REQUIRED:
            self.assertIn(name, natives, name)
        self.assertIn("Native_PumpMessageQueue", natives)
        # Offsets land inside the R+X segment, which is where bodies live.
        for offset in natives.values():
            self.assertIsInstance(offset, int)
            self.assertTrue(TEXT_VADDR <= offset < TEXT_VADDR + TEXT_SIZE, hex(offset))

    def test_signature_parsing(self) -> None:
        data = json.loads(self.json_result.stdout)
        self.assertEqual(len(data["game_app_args"]), 7)
        self.assertEqual(data["game_app_args"][0], "Lcom/popcap/SexyAppFramework/AndroidSurfaceView")
        self.assertEqual(data["game_app_args"][-1], "Lcom/popcap/SexyAppFramework/AndroidNotification")

    def test_padding_from_movs(self) -> None:
        data = json.loads(self.json_result.stdout)
        self.assertEqual(data["surface_changed_pad"], 1)
        self.assertFalse(data["surface_changed_pad_assumed"])

    def test_entry_skeleton_is_pasteable(self) -> None:
        text = self.run_result.stdout
        self.assertIn(".game_app_init_args      = kGameAppInitArgs961", text)
        self.assertIn(".surface_changed_pad = 1", text)
        self.assertIn(".fingerprint_draw_frame", text)
        self.assertIn("Native_DoSomethingElse", text)  # unused natives are still listed

    def test_other_natives_listed(self) -> None:
        data = json.loads(self.json_result.stdout)
        names = {n["name"] for n in data["other_natives"]}
        self.assertIn("Native_DoSomethingElse", names)

    def test_rejects_non_arm(self) -> None:
        bad = os.path.join(self.tmp.name, "x86.so")
        with open(bad, "wb") as fh:
            fh.write(b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8 +
                     struct.pack("<HH", 3, 3) + b"\x00" * 32)
        result = subprocess.run([sys.executable, TOOL, bad], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not ARM", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
