#ifndef PVZ2NATIVE_GAME_BUILD_SCAN_H
#define PVZ2NATIVE_GAME_BUILD_SCAN_H

#include <cstdint>

#include <pvz2native/elf32/elf32_loader.h>
#include <pvz2native/game/symbols.h>

namespace pvz2native {

/* What a scan of an unidentified image concluded -- enough to log a truthful
 * report whether the answer is yes or no, and enough for a player to paste the
 * offsets of a new build into an issue without owning a disassembler. */
struct BuildScanReport {
    bool identified = false;
    char name[64] = {};         /* e.g. "scanned: 20 MB, 22 natives"             */
    std::uint32_t tables = 0;   /* JNINativeMethod entries that validated whole  */
    std::uint32_t mapped = 0;   /* entries we have a use for                     */
    std::uint32_t required_missing = 0;
    std::uint32_t game_app_args = 0;
    std::uint32_t surface_changed_pad = 1;
    /* Names the boot cannot do without that the image does not declare, as one
     * comma-separated line. Long enough for all eight with their full names.
     * Empty when identified. */
    char missing[384] = {};
};

/* Identifies a build that is not in kVersions by reading its RegisterNatives
 * tables out of the loaded image.
 *
 * Why this can work at all: JNI_OnLoad registers the lifecycle natives with
 * RegisterNatives, so they are invisible to the dynamic symbol table -- but the
 * tables it hands over are ordinary data, {name, signature, function} triples
 * whose name field points at a plain string ("Native_onDrawFrame"). Those
 * strings and the table shape have been stable from 4.5.2 through 9.6.1, which
 * is exactly the span the PvZ2 mods rebase from (Grind Thousand, Reflourished,
 * ECLISE, ...). A mod moves every address, but it does not rename the methods
 * the framework calls, so the natives can be found by name and their addresses
 * read out of the table instead of being written down here.
 *
 * What it CANNOT recover: the engine globals and field offsets (LawnApp,
 * AndroidAppDriver, Board, the patch addresses). Those are not named anywhere
 * in the image, so they stay 0 -- "not mapped" -- and every feature that reads
 * them (Rich Presence detail, custom difficulties, the store rewrites, the
 * diagnostics) stays off until someone maps that build by hand. Booting is the
 * part this buys.
 *
 * Returns true and fills `out` when the image declares every native the boot
 * sequence drives. The strings `out` points at live in storage owned by
 * build_scan.cpp; it is valid until the next scan_build() call, and never
 * freed, so a single call per process is the intended use (which is what
 * game_symbols_detect does). */
bool scan_build(const pvz2_elf_image_t *img, GameSymbols *out, BuildScanReport *report);

}  // namespace pvz2native

#endif
