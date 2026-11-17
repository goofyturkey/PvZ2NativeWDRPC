/* Self-test for game/build_scan.cpp -- it does not link the game.
 *
 * The scanner's whole job is to read a stranger's libPVZ2.so correctly, and the
 * one thing this repository cannot ship is a stranger's libPVZ2.so. So the test
 * builds small synthetic images with the same shape: a flat guest address space,
 * JNINativeMethod arrays as real 12-byte {name, signature, function} triples,
 * names in "rodata", function bodies in "text". That covers the parts the scan
 * can get wrong -- the triple validation, the neighbour rule, the signature
 * parse, the surfaceChanged pad -- without needing anyone's APK.
 *
 * Build and run:
 *   g++ -std=c++20 -Ipvz2native/include \
 *       pvz2native/src/game/build_scan.cpp pvz2native/tests/build_scan_test.cpp \
 *       -o /tmp/build_scan_test && /tmp/build_scan_test
 */

#include <pvz2native/game/build_scan.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* build_scan.cpp logs its findings; the test wants the findings, not the log. */
extern "C" void pvz2_log(const char *, ...) {}

namespace {

struct FakeImage {
    std::vector<std::uint8_t> mem = std::vector<std::uint8_t>(0x100000, 0);
    pvz2_elf_image_t img{};

    static constexpr std::uint32_t kBase = 0x10000;
    static constexpr std::uint32_t kSpan = 0x80000;
    static constexpr std::uint32_t kTextOffset = 0x30000; /* unbiased */
    static constexpr std::uint32_t kTextSize = 0x10000;

    FakeImage() {
        img.mem = mem.data();
        img.mem_size = (std::uint32_t)mem.size();
        img.so_base = kBase;
        img.so_span = kSpan;
        img.text_vaddr = kTextOffset;
        img.text_size = kTextSize;
    }

    void put_u32(std::uint32_t va, std::uint32_t v) { std::memcpy(&mem[va], &v, 4); }
    std::uint32_t text_va(std::uint32_t at) const { return kBase + kTextOffset + at; }

    std::uint32_t add_string(const char *s) {
        const std::uint32_t at = next_string;
        std::memcpy(&mem[at], s, std::strlen(s) + 1);
        next_string += (std::uint32_t)std::strlen(s) + 1;
        next_string = (next_string + 3) & ~3u;
        return at;
    }

    /* A native's body: a PUSH {r4,lr}, optionally followed by the MOVs that tell
     * the scanner which registers it reads its arguments from. */
    std::uint32_t add_function(const std::uint32_t *extra, std::size_t extra_count) {
        const std::uint32_t at = text_va(fn_at);
        put_u32(at, 0xE92D4010u); /* PUSH {r4,lr} */
        for (std::size_t i = 0; i < extra_count; ++i) put_u32(at + 4 + (std::uint32_t)i * 4, extra[i]);
        put_u32(at + 4 + (std::uint32_t)extra_count * 4, 0xE12FFF1Eu); /* BX LR */
        fn_at += 0x40;
        return at;
    }

    std::uint32_t add_entry(const char *name, const char *sig, std::uint32_t fn) {
        const std::uint32_t at = next_entry;
        put_u32(at, add_string(name));
        put_u32(at + 4, add_string(sig));
        put_u32(at + 8, fn);
        next_entry += 12;
        return at;
    }

    std::uint32_t next_string = kBase + 0x1000;
    std::uint32_t next_entry = kBase + 0x60000;
    std::uint32_t fn_at = 0;
};

constexpr char kSig7[] =
    "(Lcom/popcap/SexyAppFramework/AndroidSurfaceView;"
    "Lcom/popcap/SexyAppFramework/AndroidHttpProxy;"
    "Lcom/popcap/SexyAppFramework/cloud/Cloud;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayConnect;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayAchievements;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayLeaderboard;"
    "Lcom/popcap/SexyAppFramework/AndroidNotification;)Z";

constexpr char kSig8[] =
    "(Lcom/popcap/SexyAppFramework/AndroidSurfaceView;"
    "Lcom/popcap/SexyAppFramework/AndroidHttpProxy;"
    "Lcom/popcap/SexyAppFramework/AndroidFacebookDriver;"
    "Lcom/popcap/SexyAppFramework/cloud/Cloud;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayConnect;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayAchievements;"
    "Lcom/popcap/SexyAppFramework/GooglePlay/GooglePlayLeaderboard;"
    "Lcom/popcap/SexyAppFramework/AndroidNotification;)Z";

/* The signature each Java declaration uses -- the same strings the scan checks
 * an entry against. */
const char *sig_for(const char *name) {
    if (std::strcmp(name, "Native_GameAppInitialize") == 0) return kSig7;
    if (std::strcmp(name, "Native_applicationWillFinishLaunching") == 0) return "(Ljava/lang/String;)V";
    if (std::strcmp(name, "Native_onSurfaceChanged") == 0) return "(II)V";
    if (std::strncmp(name, "Native_Notify", 13) == 0) return "(Z)V";
    return "()V";
}

int g_failures = 0;

void check(bool cond, const char *what) {
    if (cond) return;
    std::printf("  FAIL: %s\n", what);
    ++g_failures;
}

/* The seven required natives, minus whichever the caller leaves out, plus the
 * optional ones a modern build also carries. */
void add_modern_natives(FakeImage &f, const char *omit = nullptr) {
    struct Row {
        const char *name;
        const char *sig;
        bool surface_changed;
    };
    const Row rows[] = {
        {"Native_GameAppInitialize", kSig7, false},
        {"Native_applicationWillFinishLaunching", "(Ljava/lang/String;)V", false},
        {"Native_applicationDidFinishLaunching", "()V", false},
        {"Native_applicationWillBecomeForeground", "()V", false},
        {"Native_applicationDidBecomeActive", "()V", false},
        {"Native_onSurfaceCreated", "()V", false},
        {"Native_onSurfaceChanged", "(II)V", true},
        {"Native_onDrawFrame", "()V", false},
        {"Native_PumpMessageQueue", "()V", false},
    };
    for (const Row &r : rows) {
        if (omit != nullptr && std::strcmp(omit, r.name) == 0) continue;
        std::uint32_t fn;
        if (r.surface_changed) {
            const std::uint32_t movs[] = {0xE1A05002u /* MOV r5,r2 */, 0xE1A04003u /* MOV r4,r3 */};
            fn = f.add_function(movs, 2);
        } else {
            fn = f.add_function(nullptr, 0);
        }
        f.add_entry(r.name, r.sig, fn);
    }
}

void test_modern_build_identifies() {
    std::printf("modern build (7 objects, MOVs off r2/r3)\n");
    FakeImage f;
    add_modern_natives(f);

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    const bool ok = pvz2native::scan_build(&f.img, &syms, &report);
    check(ok, "scan identifies the image");
    check(report.identified, "report says identified");
    check(syms.native.on_draw_frame != 0, "onDrawFrame mapped");
    check(syms.native.game_app_initialize != 0, "GameAppInitialize mapped");
    check(syms.native.on_surface_changed != 0, "onSurfaceChanged mapped");
    check(syms.native.pump_message_queue != 0, "PumpMessageQueue mapped");
    check(syms.native.notify_surface_change == 0, "absent Notify* stays unmapped");
    check(syms.game_app_init_arg_count == 7, "seven objects parsed from the signature");
    check(syms.surface_changed_pad == 1, "pad 1 from MOV r5,r2 / MOV r4,r3");
    check(syms.game_app_init_args != nullptr, "argument array attached");
    if (syms.game_app_init_args != nullptr && syms.game_app_init_arg_count == 7) {
        check(std::strcmp(syms.game_app_init_args[0],
                          "Lcom/popcap/SexyAppFramework/AndroidSurfaceView") == 0,
              "first object is the surface view");
        check(std::strcmp(syms.game_app_init_args[6],
                          "Lcom/popcap/SexyAppFramework/AndroidNotification") == 0,
              "last object is the notification manager");
    }
}

void test_legacy_build_eight_objects() {
    std::printf("legacy build (8 objects, MOVs off r3/r4)\n");
    FakeImage f;
    const std::uint32_t movs[] = {0xE1A05003u /* MOV r5,r3 */, 0xE1A04004u /* MOV r4,r4 */};
    const std::uint32_t fn = f.add_function(movs, 2);
    f.add_entry("Native_GameAppInitialize", kSig8, fn);
    const char *names[] = {"Native_applicationWillFinishLaunching", "Native_applicationDidFinishLaunching",
                           "Native_applicationWillBecomeForeground", "Native_applicationDidBecomeActive",
                           "Native_onSurfaceCreated", "Native_onSurfaceChanged", "Native_onDrawFrame"};
    for (const char *n : names) f.add_entry(n, sig_for(n), f.add_function(movs, 2));

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(pvz2native::scan_build(&f.img, &syms, &report), "scan identifies the legacy image");
    check(syms.game_app_init_arg_count == 8, "eight objects parsed");
    check(syms.surface_changed_pad == 2, "pad 2 from MOVs off r3/r4");
}

void test_missing_required_native_refused() {
    std::printf("missing Native_onDrawFrame\n");
    FakeImage f;
    add_modern_natives(f, "Native_onDrawFrame");

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(!pvz2native::scan_build(&f.img, &syms, &report), "scan refuses the image");
    check(!report.identified, "report says not identified");
    check(std::strstr(report.missing, "Native_onDrawFrame") != nullptr,
          "the refusal names the missing native");
}

void test_single_entry_array_still_maps() {
    std::printf("own one-entry table (createNativeApplicationLifecycleObserver)\n");
    FakeImage f;
    add_modern_natives(f);
    /* 9.6.1 registers this one in a JNINativeMethod array of its own, so it has
     * no neighbour to vouch for it -- and its absence would leave work that
     * moved into it undone, silently. */
    f.add_entry("Native_createNativeApplicationLifecycleObserver", "()V", f.add_function(nullptr, 0));

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(pvz2native::scan_build(&f.img, &syms, &report), "scan still identifies the build");
    check(syms.native.create_lifecycle_observer != 0, "the one-entry table is mapped");
}

void test_wrong_signature_ignored() {
    std::printf("known name with somebody else's signature\n");
    FakeImage f;
    /* A triple whose name is ours but whose signature is another method's: the
     * signature check must keep it out of the map rather than call it. */
    f.add_entry("Native_onDrawFrame", "(II)V", f.add_function(nullptr, 0));

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(!pvz2native::scan_build(&f.img, &syms, &report), "mismatched signature is refused");
    check(syms.native.on_draw_frame == 0, "nothing was mapped from it");
    check(std::strstr(report.missing, "Native_onDrawFrame") != nullptr,
          "refusal names the native it could not trust");
}

void test_empty_image_refused() {
    std::printf("blank image\n");
    FakeImage f;
    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(!pvz2native::scan_build(&f.img, &syms, &report), "blank image is refused");
    check(std::strstr(report.missing, "no JNINativeMethod tables") != nullptr,
          "refusal says no tables were found");
}

void test_bad_signature_refused() {
    std::printf("GameAppInitialize with an unparsable signature\n");
    FakeImage f;
    const std::uint32_t fn = f.add_function(nullptr, 0);
    /* Right shape ("(L...") but an array argument, which no GameAppInitialize
     * has and which the argument parser refuses rather than misalign. */
    f.add_entry("Native_GameAppInitialize", "(Lcom/foo/Bar;[I)V", fn);
    const char *names[] = {"Native_applicationWillFinishLaunching", "Native_applicationDidFinishLaunching",
                           "Native_applicationWillBecomeForeground", "Native_applicationDidBecomeActive",
                           "Native_onSurfaceCreated", "Native_onSurfaceChanged", "Native_onDrawFrame"};
    for (const char *n : names) f.add_entry(n, sig_for(n), f.add_function(nullptr, 0));

    pvz2native::GameSymbols syms{};
    pvz2native::BuildScanReport report{};
    check(!pvz2native::scan_build(&f.img, &syms, &report), "no objects means no boot");
    check(std::strstr(report.missing, "signature") != nullptr, "refusal mentions the signature");
}

}  // namespace

int main() {
    test_modern_build_identifies();
    test_legacy_build_eight_objects();
    test_missing_required_native_refused();
    test_single_entry_array_still_maps();
    test_wrong_signature_ignored();
    test_empty_image_refused();
    test_bad_signature_refused();
    if (g_failures != 0) {
        std::printf("%d check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("all checks passed\n");
    return 0;
}
