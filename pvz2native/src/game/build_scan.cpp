/* Structural identification of a libPVZ2.so whose address table we do not have.
 *
 * The version table in symbols.cpp is the fast path: three known builds whose
 * natives were read out of their JNINativeMethod arrays by hand. A mod
 * (Grind Thousand, Reflourished, ECLISE, and whatever comes next) rebases one of
 * those builds and rewrites parts of it, which moves every address -- so no
 * table entry matches, and game_symbols_detect used to refuse to boot. That is
 * the honest behaviour, but it is also a dead end for every mod, because the ONE
 * thing a mod does not change is the set of Java methods the framework calls.
 *
 * Those methods are registered with RegisterNatives from JNINativeMethod arrays
 * that are plain data in the image:
 *
 *     { const char *name; const char *signature; void (*fn)(void); }
 *
 * The loader relocates the image, so by the time this runs each of those fields
 * IS the guest address it would be on a device, and the name field points at a
 * NUL-terminated string ("Native_onDrawFrame") in .rodata. Two consequences:
 *
 *   1. every native the harness drives can be located by NAME, not by offset;
 *   2. the signature string carries GameAppInitialize's declared objects, which
 *      is per-version data symbols.cpp otherwise has to be told (seven objects
 *      since 9.6.1, eight before -- getting that wrong shifts every object one
 *      register and corrupts the screen size instead of failing).
 *
 * So the scan walks the image for 12-byte {name, sig, fn} triples that validate
 * whole, keeps the ones that name a method we use, and refuses unless every
 * native the boot sequence calls is present. The strings have been identical
 * from 4.5.2 (2016) through 9.6.1 (2021), which is the whole span the mod
 * scene rebases from.
 *
 * What this deliberately does NOT do is guess. Field offsets inside the engine
 * (LawnApp, AndroidAppDriver, Board) and the patch call sites are not named in
 * the image, so they stay 0 -- "not mapped" -- and the features that read them
 * stay off. A build identified this way boots; it does not get Rich Presence
 * detail, the custom difficulties, the store rewrites or the diagnostics until
 * its globals are mapped by hand. The scan prints every native it found, at its
 * offset, which is exactly the report needed to write that entry later. */

#include <pvz2native/game/build_scan.h>

#include <pvz2native/log.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

namespace pvz2native {
namespace {

/* The most objects Native_GameAppInitialize may declare. The real list is seven
 * or eight; the cap matches runtime/guest_memmap.h's kFakeObjMax minus thiz, and
 * a signature longer than this is not a build this harness can drive anyway. */
constexpr std::uint32_t kMaxArgs = 15;

/* Longest method name / signature accepted. Real ones are 20 and ~400 bytes. */
constexpr std::uint32_t kMaxNameLen = 96;
constexpr std::uint32_t kMaxSigLen = 1024;

/* The RegisterNatives entries we have a use for, and where each one lands in
 * GameSymbols. Anything else in the image's tables is somebody's business but
 * not this port's -- except that it is still printed, because it is the map for
 * the next build. */
enum class Field {
    kNone,
    kGameAppInitialize,
    kWillFinishLaunching,
    kDidFinishLaunching,
    kWillBecomeForeground,
    kDidBecomeActive,
    kSurfaceCreated,
    kSurfaceChanged,
    kDrawFrame,
    kPumpMessageQueue,
    kLifecycleObserver,
    kNotifySurface,
    kNotifyRunning,
    kNotifyFocus,
    kHttpResponse,
    kHttpData,
    kHttpComplete,
    kHttpError,
};

struct NativeName {
    const char *name;
    Field field;
    bool required; /* the boot sequence cannot run without it */
};

/* Names come from the Java declarations (classesdex/), not from the disassembly:
 * AndroidSurfaceView declares Native_onDrawFrame / Native_onSurfaceChanged /
 * Native_onSurfaceCreated, AndroidGameApp the lifecycle family, and the HTTP
 * callbacks are the four registered so Java can hand results back. The last four
 * predate the Native_ prefix and are the only non-prefixed ones we look for. */
const NativeName kNativeNames[] = {
    {"Native_GameAppInitialize", Field::kGameAppInitialize, true},
    {"Native_applicationWillFinishLaunching", Field::kWillFinishLaunching, true},
    {"Native_applicationDidFinishLaunching", Field::kDidFinishLaunching, true},
    {"Native_applicationWillBecomeForeground", Field::kWillBecomeForeground, true},
    {"Native_applicationDidBecomeActive", Field::kDidBecomeActive, true},
    {"Native_onSurfaceCreated", Field::kSurfaceCreated, true},
    {"Native_onSurfaceChanged", Field::kSurfaceChanged, true},
    {"Native_onDrawFrame", Field::kDrawFrame, true},
    /* Registered WITHOUT the Native_ prefix in 9.6.1 and everything derived
     * from it -- the surface family sits in one array and this entry is the odd
     * one out. Missing it is not cosmetic: on a 9.x-family build the frame loop
     * must drain the lifecycle queue before drawing, or applicationDidBecome-
     * Active never clears the driver's "skip this frame" byte and the window
     * stays black with no error. */
    {"PumpMessageQueue", Field::kPumpMessageQueue, false},
    {"Native_PumpMessageQueue", Field::kPumpMessageQueue, false}, /* if a build prefixes it */
    {"Native_createNativeApplicationLifecycleObserver", Field::kLifecycleObserver, false},
    {"Native_NotifySurfaceChange", Field::kNotifySurface, false},
    {"Native_NotifyAppRunning", Field::kNotifyRunning, false},
    {"Native_NotifyFocusChange", Field::kNotifyFocus, false},
    {"HttpReceivedResponse", Field::kHttpResponse, false},
    {"HttpReceivedData", Field::kHttpData, false},
    {"HttpTransactionComplete", Field::kHttpComplete, false},
    {"HttpTransactionError", Field::kHttpError, false},
};

const NativeName *name_lookup(const char *name) {
    for (const NativeName &n : kNativeNames) {
        if (std::strcmp(n.name, name) == 0) return &n;
    }
    return nullptr;
}

constexpr std::size_t kNativeNames_count = sizeof(kNativeNames) / sizeof(kNativeNames[0]);

/* Reads the field a name maps to, so a second sighting of the same name cannot
 * overwrite the first. */
std::uint32_t field_value(const GameSymbols &s, Field field) {
    switch (field) {
        case Field::kGameAppInitialize:    return s.native.game_app_initialize;
        case Field::kWillFinishLaunching:  return s.native.application_will_finish_launching;
        case Field::kDidFinishLaunching:   return s.native.application_did_finish_launching;
        case Field::kWillBecomeForeground: return s.native.application_will_become_foreground;
        case Field::kDidBecomeActive:      return s.native.application_did_become_active;
        case Field::kSurfaceCreated:       return s.native.on_surface_created;
        case Field::kSurfaceChanged:       return s.native.on_surface_changed;
        case Field::kDrawFrame:            return s.native.on_draw_frame;
        case Field::kPumpMessageQueue:     return s.native.pump_message_queue;
        case Field::kLifecycleObserver:    return s.native.create_lifecycle_observer;
        case Field::kNotifySurface:        return s.native.notify_surface_change;
        case Field::kNotifyRunning:        return s.native.notify_app_running;
        case Field::kNotifyFocus:          return s.native.notify_focus_change;
        case Field::kHttpResponse:         return s.jni_native.http_received_response;
        case Field::kHttpData:             return s.jni_native.http_received_data;
        case Field::kHttpComplete:         return s.jni_native.http_transaction_complete;
        case Field::kHttpError:            return s.jni_native.http_transaction_error;
        case Field::kNone:                 return 0;
    }
    return 0;
}

/* Storage behind the GameSymbols a scan hands out. GameSymbols holds raw
 * pointers, so these have to outlive every reader -- static, and only ever
 * written by one scan per process (see the header). */
char g_version[16] = "auto";
char g_arg_storage[kMaxArgs][kMaxNameLen];
const char *g_arg_names[kMaxArgs] = {};

/* A view of the main image as guest addresses, which is how everything else in
 * this repository addresses it: img->mem is indexed BY VA, and so_base is the
 * load bias (so_span is unbiased, hence the addition). */
struct Image {
    const pvz2_elf_image_t *img;
    std::uint32_t lo;
    std::uint32_t hi;
    std::uint32_t text_lo;
    std::uint32_t text_hi;

    bool has(std::uint32_t va, std::uint32_t n) const {
        return va >= lo && (std::uint64_t)va + n <= hi;
    }
    std::uint32_t u32(std::uint32_t va) const {
        std::uint32_t v = 0;
        std::memcpy(&v, img->mem + va, sizeof(v));
        return v;
    }
    const char *bytes(std::uint32_t va) const { return (const char *)(img->mem + va); }
    bool in_text(std::uint32_t va) const { return text_hi > text_lo && va >= text_lo && va < text_hi; }
};

bool readable_string(const Image &im, std::uint32_t va, std::uint32_t max_len, bool identifier,
                     std::uint32_t *out_len) {
    if (!im.has(va, 1)) return false;
    const char *s = im.bytes(va);
    for (std::uint32_t i = 0; i < max_len; ++i) {
        if (!im.has(va + i, 1)) return false;
        const unsigned char c = (unsigned char)s[i];
        if (c == 0) {
            *out_len = i;
            return true;
        }
        if (identifier) {
            const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '_' || c == '$';
            if (!ok) return false;
        } else if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return false;
}

/* A JNI signature's alphabet: type descriptors, class separators and the
 * letters/digits/underscores of a class name. Anything else -- notably a printf
 * format string like "(%d x %d)", which has the same shape -- is not one. */
bool plausible_signature(const Image &im, std::uint32_t va, std::uint32_t len) {
    const char *s = im.bytes(va);
    for (std::uint32_t i = 0; i < len; ++i) {
        const char c = s[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '(' || c == ')' || c == '[' ||
                        c == ']' || c == ';' || c == '/' || c == '_' || c == '$';
        if (!ok) return false;
    }
    return true;
}

/* A first instruction that cannot start a function we would call: all-zero (an
 * unmapped or unrelocated slot) or the unconditional space, which is where the
 * SVC import trampolines and coprocessor encodings live. Natives are otherwise
 * free to be one instruction -- several lifecycle ones are a bare `BX LR` -- so
 * this is a sanity check, not a prologue pattern match. */
bool plausible_code(const Image &im, std::uint32_t va) {
    if (va == 0 || !im.has(va, 4)) return false;
    const std::uint32_t insn = im.u32(va);
    return insn != 0 && (insn & 0xF0000000u) != 0xF0000000u;
}

/* One validated table entry. `at` is its address in the image, kept so entries
 * can be grouped: a real table has neighbours 12 bytes apart, whereas a stray
 * {pointer, pointer, pointer} triple that happens to look right usually does
 * not. Grouping is NOT required to use an entry, though -- a table may hold a
 * single method (9.6.1 registers createNativeApplicationLifecycleObserver in an
 * array of its own), and dropping those would lose exactly the native whose
 * absence breaks a 9.x boot silently. What is required is a known name whose
 * JNI signature fits that method: see signature_fits(). */
struct Entry {
    std::uint32_t at;
    std::uint32_t name_va;
    std::uint32_t sig_va;
    std::uint32_t fn;
    const NativeName *known; /* nullptr: a native we have no use for */
    char name[kMaxNameLen];
};

/* Marks every entry that has another entry 12 bytes before or after it. Done in
 * one sorted pass because the naive form is O(n^3) by the time the required-
 * native sweep asks again for each of eight names. */
void mark_neighbours(std::vector<Entry> &entries, std::vector<bool> *out) {
    std::vector<std::size_t> order(entries.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(),
              [&](std::size_t a, std::size_t b) { return entries[a].at < entries[b].at; });
    out->assign(entries.size(), false);
    for (std::size_t k = 0; k < order.size(); ++k) {
        const std::uint32_t at = entries[order[k]].at;
        if (k > 0 && entries[order[k - 1]].at + 12 == at) (*out)[order[k]] = true;
        if (k + 1 < order.size() && entries[order[k + 1]].at == at + 12) (*out)[order[k]] = true;
    }
}

/* The signature that goes with each name we use, as declared by the Java side
 * (classesdex/). Checking it is what lets a single ungrouped triple be trusted:
 * a name string that happens to sit next to some other table's signature is
 * rejected here instead of mapping the wrong function.
 *
 * Nothing else about these has changed between 4.5.2 and 9.6.1, which is why
 * they can be written down at all. */
bool signature_fits(Field field, const char *sig) {
    struct Expect {
        Field field;
        const char *sig; /* exact, or a prefix when it ends in '*' */
    };
    static const Expect kExpected[] = {
        {Field::kGameAppInitialize, "(L*"},
        {Field::kWillFinishLaunching, "(Ljava/lang/String;)V"},
        {Field::kDidFinishLaunching, "()V"},
        {Field::kWillBecomeForeground, "()V"},
        {Field::kDidBecomeActive, "()V"},
        {Field::kSurfaceCreated, "()V"},
        {Field::kSurfaceChanged, "(II)V"},
        {Field::kDrawFrame, "()V"},
        {Field::kPumpMessageQueue, "()V"},
        {Field::kNotifySurface, "(Z)V"},
        {Field::kNotifyRunning, "(Z)V"},
        {Field::kNotifyFocus, "(Z)V"},
        {Field::kHttpResponse, "(J)V"},
        {Field::kHttpData, "(J[BI)V"},
        {Field::kHttpComplete, "(J)V"},
        {Field::kHttpError, "(J)V"},
    };
    for (const Expect &e : kExpected) {
        if (e.field != field) continue;
        const std::size_t n = std::strlen(e.sig);
        if (n > 0 && e.sig[n - 1] == '*') return std::strncmp(sig, e.sig, n - 1) == 0;
        return std::strcmp(sig, e.sig) == 0;
    }
    /* createNativeApplicationLifecycleObserver is the one native whose signature
     * was never read off a build we could compare; accept any JNI signature for
     * it rather than guess. */
    return true;
}

/* Native_onSurfaceChanged reads its size from the register pair its caller put
 * it in, and which pair that is differs per build: {r2,r3} for every build from
 * 4.5.2 on, {r3,r4} for 1.6, {r1,r2} for none we have seen. Getting it wrong is
 * silent -- the engine derives its projection matrix from those two values.
 *
 * All we need is which registers the body moves out of first, so look for
 * `MOV Rd, Rm` (the only form that survives whatever the compiler did to the
 * frame) and take the lowest pair. No matches means no evidence, and the
 * default is what every build since 4.5.2 uses. */
std::uint32_t infer_surface_pad(const Image &im, std::uint32_t fn, bool *assumed) {
    bool from[5] = {false, false, false, false, false}; /* registers 0..4 */
    for (std::uint32_t i = 0; i < 16; ++i) {
        if (!im.has(fn + i * 4, 4)) break;
        const std::uint32_t w = im.u32(fn + i * 4);
        /* MOV Rd, Rm: cond 1110, 0001 1010 0000, S=0, Rd, 0000, Rm. The
         * mask clears Rd (12..15) and Rm (0..3); everything between them is
         * already 0 in this encoding, which is what tells it apart from the
         * other data-processing forms. */
        if ((w & 0x0FEF0000u) != 0x01A00000u) continue;
        const std::uint32_t rm = w & 0xFu;
        if (rm < 5) from[rm] = true;
    }
    *assumed = false;
    if (from[3] && from[4]) return 2;
    if (from[2] && from[3]) return 1;
    if (from[1] && from[2]) return 0;
    *assumed = true;
    return 1;
}

/* Reads GameAppInitialize's declared object list out of its JNI signature, e.g.
 *   (Lcom/popcap/SexyAppFramework/AndroidSurfaceView;...;L.../AndroidNotification;)Z
 * -> the seven class names, in order. This is the per-version data symbols.cpp
 * normally writes down, recovered from the image instead. */
std::uint32_t parse_game_app_args(const Image &im, std::uint32_t sig_va, std::uint32_t sig_len,
                                  BuildScanReport *report) {
    if (sig_len < 3 || !im.has(sig_va, sig_len + 1) || im.bytes(sig_va)[0] != '(') return 0;
    const char *sig = im.bytes(sig_va);
    const std::uint32_t end = sig_len;

    std::uint32_t count = 0;
    std::uint32_t i = 1;
    while (i < end && sig[i] != ')') {
        if (sig[i] == 'L') {
            std::uint32_t semi = i + 1;
            while (semi < end && sig[semi] != ';') ++semi;
            if (semi >= end) return 0;
            const std::uint32_t len = semi - i; /* including the L */
            if (len + 1 > kMaxNameLen) return 0;
            if (count >= kMaxArgs) return 0;
            std::memcpy(g_arg_storage[count], sig + i, len);
            g_arg_storage[count][len] = '\0';
            g_arg_names[count] = g_arg_storage[count];
            ++count;
            i = semi + 1;
        } else if (sig[i] == '[') {
            /* Arrays are not objects this harness can fabricate, and no build
             * has declared one -- refuse rather than misalign the list. */
            return 0;
        } else {
            ++i;
        }
    }
    if (i >= end || sig[i] != ')') return 0;
    report->game_app_args = count;
    /* A zero-argument GameAppInitialize cannot initialize anything, so an empty
     * list means this is not the method we think it is. */
    return count;
}

void assign_native(GameSymbols *out, Field field, std::uint32_t fn) {
    switch (field) {
        case Field::kGameAppInitialize:    out->native.game_app_initialize = fn; break;
        case Field::kWillFinishLaunching:  out->native.application_will_finish_launching = fn; break;
        case Field::kDidFinishLaunching:   out->native.application_did_finish_launching = fn; break;
        case Field::kWillBecomeForeground: out->native.application_will_become_foreground = fn; break;
        case Field::kDidBecomeActive:      out->native.application_did_become_active = fn; break;
        case Field::kSurfaceCreated:       out->native.on_surface_created = fn; break;
        case Field::kSurfaceChanged:       out->native.on_surface_changed = fn; break;
        case Field::kDrawFrame:            out->native.on_draw_frame = fn; break;
        case Field::kPumpMessageQueue:     out->native.pump_message_queue = fn; break;
        case Field::kLifecycleObserver:    out->native.create_lifecycle_observer = fn; break;
        case Field::kNotifySurface:        out->native.notify_surface_change = fn; break;
        case Field::kNotifyRunning:        out->native.notify_app_running = fn; break;
        case Field::kNotifyFocus:          out->native.notify_focus_change = fn; break;
        case Field::kHttpResponse:         out->jni_native.http_received_response = fn; break;
        case Field::kHttpData:             out->jni_native.http_received_data = fn; break;
        case Field::kHttpComplete:         out->jni_native.http_transaction_complete = fn; break;
        case Field::kHttpError:            out->jni_native.http_transaction_error = fn; break;
        case Field::kNone:                 break;
    }
}

}  // namespace

bool scan_build(const pvz2_elf_image_t *img, GameSymbols *out, BuildScanReport *report) {
    if (img == nullptr || out == nullptr || report == nullptr || img->mem == nullptr) return false;
    *out = GameSymbols{};
    *report = BuildScanReport{};

    Image im{};
    im.img = img;
    im.lo = img->so_base;
    im.hi = img->so_base + img->so_span;
    /* so_span comes from the PT_LOAD headers, the buffer from the loader; trust
     * the smaller of the two rather than reading past the allocation. */
    if (im.hi > img->mem_size) im.hi = img->mem_size;
    if (im.hi <= im.lo || im.hi - im.lo < 12) return false;
    im.text_lo = img->text_size != 0 ? img->so_base + img->text_vaddr : 0;
    im.text_hi = img->text_size != 0 ? im.text_lo + img->text_size : 0;

    /* One linear pass over the image. The filter is deliberately cheap: a word
     * that points into the image and whose first byte is an upper-case letter,
     * which every native name starts with. It is NOT filtered on a "Native_"
     * prefix -- 9.6.1 registers Native_PumpMessageQueue as bare
     * "PumpMessageQueue", and assuming the prefix silently lost the one native
     * whose absence leaves a 9.x build drawing nothing. Anything that survives
     * is validated whole, so the pass costs a word compare per 4 bytes rather
     * than a string read. */
    std::vector<Entry> entries;
    /* Set when a name we know turns up beside a signature that belongs to some
     * other method: worth saying out loud, because that is the shape of a
     * misread table, and otherwise the report would be a bare "found nothing". */
    char ignored[192] = {};
    const std::uint32_t span = im.hi - im.lo;
    for (std::uint32_t off = 0; off + 12 <= span; off += 4) {
        const std::uint32_t at = im.lo + off;
        const std::uint32_t name_va = im.u32(at);
        if (!im.has(name_va, 1)) continue;
        const char first = im.bytes(name_va)[0];
        if (first < 'A' || first > 'Z') continue;

        std::uint32_t name_len = 0;
        if (!readable_string(im, name_va, kMaxNameLen, true, &name_len) || name_len < 6) continue;

        const std::uint32_t sig_va = im.u32(at + 4);
        std::uint32_t sig_len = 0;
        if (!readable_string(im, sig_va, kMaxSigLen, false, &sig_len) || sig_len < 3) continue;
        if (im.bytes(sig_va)[0] != '(' || std::memchr(im.bytes(sig_va), ')', sig_len) == nullptr) continue;
        if (!plausible_signature(im, sig_va, sig_len)) continue;

        /* The function has to be code in this image -- in the R+X segment when
         * the loader told us where it is, anywhere in the image otherwise.
         * Nothing stronger is possible: several lifecycle natives are a single
         * `BX LR`. */
        const std::uint32_t fn = im.u32(at + 8);
        if ((fn & 3u) != 0) continue; /* ARM code is word-aligned */
        if (im.text_hi > im.text_lo ? !im.in_text(fn) : (fn < im.lo || fn >= im.hi)) continue;
        if (!plausible_code(im, fn)) continue;

        Entry e{};
        e.at = at;
        e.name_va = name_va;
        e.sig_va = sig_va;
        e.fn = fn;
        e.known = name_lookup(im.bytes(name_va));
        std::memcpy(e.name, im.bytes(name_va), name_len);
        e.name[name_len] = '\0';
        if (e.known != nullptr && !signature_fits(e.known->field, im.bytes(sig_va))) {
            if (ignored[0] == '\0') {
                std::snprintf(ignored, sizeof(ignored), "%s has signature \"%s\", which is not its own",
                              e.name, im.bytes(sig_va));
            }
            continue;
        }
        entries.push_back(e);
        if (entries.size() >= 4096) break; /* a real build declares ~30 */
    }

    if (entries.empty()) {
        std::snprintf(report->missing, sizeof(report->missing), "%s",
                      ignored[0] != '\0' ? ignored : "no JNINativeMethod tables found");
        pvz2_log("[version] no usable RegisterNatives table: %s", report->missing);
        return false;
    }

    std::vector<bool> grouped;
    mark_neighbours(entries, &grouped);

    std::uint32_t tables = 0;
    std::uint32_t mapped = 0;
    std::vector<bool> required_present(kNativeNames_count, false);

    pvz2_log("[version] scanning %u native-table candidates", (unsigned)entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const Entry &e = entries[i];
        if (grouped[i]) ++tables;
        if (e.known == nullptr) {
            /* An entry with no use in this port -- still worth naming, because
             * it is part of the map of the build. Ungrouped ones are noise. */
            if (grouped[i]) {
                pvz2_log("[version]   %-48s .so+0x%x (unused)", e.name, (unsigned)(e.fn - im.lo));
            }
            continue;
        }
        const std::size_t name_index = (std::size_t)(e.known - kNativeNames);
        if (e.known->required) required_present[name_index] = true;
        /* An array holds each name once; a second sighting is a copy. Keep the
         * first so the offsets stay stable if a build duplicates a name. */
        if (field_value(*out, e.known->field) != 0) continue;
        pvz2_log("[version]   %-48s .so+0x%x%s", e.name, (unsigned)(e.fn - im.lo),
                 grouped[i] ? "" : " (single-entry array)");
        assign_native(out, e.known->field, e.fn);
        ++mapped;
    }

    report->tables = tables;
    report->mapped = mapped;

    /* Everything the boot sequence drives must be present, or this is not a
     * build we can start -- and saying so here is far better than calling
     * whatever address 0 is. */
    std::uint32_t missing_len = 0;
    report->missing[0] = '\0';
    for (std::size_t n = 0; n < kNativeNames_count; ++n) {
        if (!kNativeNames[n].required || required_present[n]) continue;
        ++report->required_missing;
        const int wrote = std::snprintf(report->missing + missing_len,
                                        sizeof(report->missing) - missing_len, "%s%s",
                                        missing_len ? ", " : "", kNativeNames[n].name);
        if (wrote > 0) missing_len += (std::uint32_t)wrote;
        if (missing_len >= sizeof(report->missing)) break;
    }
    if (report->required_missing != 0) return false;

    /* The argument list, from the signature that goes with the native itself. */
    std::uint32_t game_app_sig = 0;
    std::uint32_t game_app_sig_len = 0;
    for (const Entry &e : entries) {
        if (e.known != nullptr && e.known->field == Field::kGameAppInitialize) {
            game_app_sig = e.sig_va;
            game_app_sig_len = 0;
            readable_string(im, e.sig_va, kMaxSigLen, false, &game_app_sig_len);
            break;
        }
    }
    if (game_app_sig == 0 || parse_game_app_args(im, game_app_sig, game_app_sig_len, report) == 0) {
        std::snprintf(report->missing, sizeof(report->missing),
                      "Native_GameAppInitialize signature could not be parsed");
        return false;
    }

    /* The three Notify* natives and PumpMessageQueue arrived together in 9.6.1;
     * one without the other means the map is incomplete, and the symptom would
     * be a black frame rather than a failure to start. */
    if (out->native.notify_surface_change != 0 && out->native.pump_message_queue == 0) {
        pvz2_log("[version] this build declares the 9.x Notify* natives but no "
                 "PumpMessageQueue -- the lifecycle queue will not be drained");
    }

    bool pad_assumed = true;
    const std::uint32_t pad = infer_surface_pad(im, out->native.on_surface_changed, &pad_assumed);
    report->surface_changed_pad = pad;

    out->version = g_version;
    out->surface_changed_pad = pad;
    out->game_app_init_args = g_arg_names;
    out->game_app_init_arg_count = report->game_app_args;
    out->fingerprint_draw_frame = 0; /* not fingerprints: this build is not in the table */
    out->fingerprint_game_app_init = 0;

    std::snprintf(report->name, sizeof(report->name), "scanned: %u MB, %u natives, %u args",
                  (unsigned)(img->so_span >> 20), (unsigned)mapped, (unsigned)report->game_app_args);
    report->identified = true;

    pvz2_log("[version] structural identification: %u table entries, %u natives, "
             "%u GameAppInitialize objects, surfaceChanged pad %u%s",
             (unsigned)tables, (unsigned)mapped, (unsigned)report->game_app_args, (unsigned)pad,
             pad_assumed ? " (assumed)" : "");
    return true;
}

}  // namespace pvz2native
