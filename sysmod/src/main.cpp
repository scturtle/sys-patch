#include "minIni/minIni.h"
#include <algorithm> // for std::min
#include <bit>       // for std::byteswap
#include <cstring>
#include <span>
#include <switch.h>
#include <utility> // std::unreachable

namespace {

// Size of the inner heap (adjust as necessary).
constexpr u64 INNER_HEAP_SIZE = 0x1000;
// size of static buffer which memory is read into
constexpr u64 READ_BUFFER_SIZE = 0x1000;
constexpr u32 FW_VER_ANY = 0x0;
constexpr u16 REGEX_SKIP = 0x100;

// set on startup
u32 FW_VERSION;
u32 AMS_VERSION;

struct DebugEventInfo {
    u32 event_type;
    u32 flags;
    u64 thread_id;
    u64 title_id;
    u64 process_id;
    char process_name[12];
    u32 mmu_flags;
    u8 _0x30[0x10];
};

template <typename T>
constexpr void str2hex(const char *s, T *data, u8 &size) {
    // skip leading 0x (if any)
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    constexpr auto hexstr_2_nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        std::unreachable();
    };

    // parse and convert string
    while (*s != '\0') {
        if (*s == '.') {
            if (std::is_same_v<T, u16>) {
                data[size] = REGEX_SKIP;
            } else {
                std::unreachable();
            }
            s++;
        } else {
            data[size] |= hexstr_2_nibble(*s++) << 4;
            data[size] |= hexstr_2_nibble(*s++) << 0;
        }
        size++;
    }
}

struct PatternData {
    constexpr PatternData(const char *s) { str2hex(s, data, size); }
    u16 data[44]{}; // reasonable max pattern length, adjust as needed
    u8 size{};
};

struct PatchData {
    constexpr PatchData(const char *s) { str2hex(s, data, size); }
    auto cmp(const void *_data) -> bool {
        return !std::memcmp(data, _data, size);
    }
    u8 data[20]{}; // reasonable max patch length, adjust as needed
    u8 size{};
};

enum class PatchResult {
    NOT_FOUND,
    SKIPPED,
    DISABLED,
    PATCHED_FILE,
    PATCHED_SYSPATCH,
    FAILED_WRITE,
};

struct Patterns {
    const char *patch_name;         // name of patch
    const PatternData byte_pattern; // the pattern to search

    const s32 inst_offset;  // instruction offset relative to byte pattern
    const s32 patch_offset; // patch offset relative to inst_offset

    bool (*const cond)(u32 inst);                    // check condition of the instruction
    PatchData (*const patch)(u32 inst);              // the patch data to be applied
    bool (*const applied)(const u8 *data, u32 inst); // check to see if patch already applied

    bool enabled; // controlled by config.ini

    PatchResult result{PatchResult::NOT_FOUND};
};

struct PatchEntry {
    const char *name;                   // name of the system title
    const u64 title_id;                 // title id of the system title
    const std::span<Patterns> patterns; // list of patterns to find
};

constexpr auto subs_cond(u32 inst) -> bool {
    const auto type = (inst >> 21) & 0x7F9;
    const auto reg = (inst >> 16) & 0x1F;
    return (type == 0x358) && (reg == 0x01);
}

constexpr auto tbz_cond(u32 inst) -> bool {
    return ((inst >> 24) & 0x7F) == 0x36;
}

constexpr auto mov2_cond(u32 inst) -> bool {
    return (inst >> 24) == 0x2A;
}

// to view patches, use https://armconverter.com/?lock=arm64
constexpr auto nop_patch(u32 inst) -> PatchData { return "0x1F2003D5"; }
constexpr auto subs_patch(u32 inst) -> PatchData { return "0x00"; }
constexpr auto mov0_patch(u32 inst) -> PatchData { return "0xE0031FAA"; }

constexpr auto nop_applied(const u8 *data, u32 inst) -> bool {
    return nop_patch(inst).cmp(data);
}

constexpr auto subs_applied(const u8 *data, u32 inst) -> bool {
    const auto type_r = (inst >> 21) & 0x7F9;
    const auto reg = (inst >> 16) & 0x1F;
    return ((type_r == 0x358) && (reg == 0x0));
}

constexpr auto mov0_applied(const u8 *data, u32 inst) -> bool {
    return mov0_patch(inst).cmp(data);
}

constinit Patterns fs_patterns[] = {
    {"noncasigchk", "0x00090036e0230191", 0, 0, tbz_cond, nop_patch, nop_applied, true},
};

constinit Patterns ldr_patterns[] = {
    {"noacidsigchk", "0xC0035FD6..009401C0", 12, 2, subs_cond, subs_patch, subs_applied, true},
};

constinit Patterns es_patterns[] = {
    {"es", "0xE003132AF44F52A9", 0, 0, mov2_cond, mov0_patch, mov0_applied, true},
};

// https://switchbrew.org/wiki/Title_list
constinit PatchEntry patches[] = {
    {"fs", 0x0100000000000000, fs_patterns},
    {"ldr", 0x0100000000000001, ldr_patterns},
    {"es", 0x0100000000000033, es_patterns},
};

struct EmummcPaths {
    char unk[0x80];
    char nintendo[0x80];
};

void smcAmsGetEmunandConfig(EmummcPaths *out_paths) {
    SecmonArgs args{};
    args.X[0] = 0xF0000404;     /* smcAmsGetEmunandConfig */
    args.X[1] = 0;              /* EXO_EMUMMC_MMC_NAND*/
    args.X[2] = (u64)out_paths; /* out path */
    svcCallSecureMonitor(&args);
}

auto is_emummc() -> bool {
    EmummcPaths paths{};
    smcAmsGetEmunandConfig(&paths);
    return (paths.unk[0] != '\0') || (paths.nintendo[0] != '\0');
}

void patcher(Handle handle, std::span<const u8> data, u64 addr, std::span<Patterns> patterns) {
    for (auto &p : patterns) {
        // skip if disabled (controller by config.ini)
        if (p.result == PatchResult::DISABLED) {
            continue;
        }

        // skip if already patched
        if (p.result == PatchResult::PATCHED_FILE || p.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }

        for (u32 i = 0; i < data.size(); i++) {
            if (i + p.byte_pattern.size >= data.size()) {
                break;
            }

            // loop through every byte of the pattern data to find a match
            // skipping over any bytes if the value is REGEX_SKIP
            u32 count{};
            for (; count < p.byte_pattern.size; count++) {
                if (p.byte_pattern.data[count] != data[i + count] &&
                    p.byte_pattern.data[count] != REGEX_SKIP) {
                    break;
                }
            }

            // if we have found a matching pattern
            if (count == p.byte_pattern.size) {
                // fetch the instruction
                u32 inst{};
                const s32 inst_offset = (s32)i + p.inst_offset;
                if (inst_offset < 0 || inst_offset + (s32)sizeof(inst) >= (s32)data.size()) {
                    continue;
                }
                std::memcpy(&inst, data.data() + inst_offset, sizeof(inst));

                // check if the instruction is the one that we want
                if (p.cond(inst)) {
                    const auto [patch_data, patch_size] = p.patch(inst);
                    const auto patch_offset = addr + inst_offset + p.patch_offset;
                    if (inst_offset + p.patch_offset < 0 ||
                        inst_offset + p.patch_offset + patch_size >= (s32)data.size()) {
                        continue;
                    }
                    // todo: log failed writes, although this should in theory never fail
                    if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, patch_offset, patch_size))) {
                        p.result = PatchResult::FAILED_WRITE;
                    } else {
                        p.result = PatchResult::PATCHED_SYSPATCH;
                    }
                    // move onto next pattern
                    break;
                } else if (p.applied(data.data() + inst_offset + p.patch_offset, inst)) {
                    // patch already applied by sigpatches
                    p.result = PatchResult::PATCHED_FILE;
                    break;
                }
            }
        }
    }
}

auto apply_patch(const PatchEntry &patch) -> bool {
    Handle handle{};
    DebugEventInfo event_info{};

    u64 pids[0x50]{};
    s32 process_count{};
    static u8 buffer[READ_BUFFER_SIZE];

    if (R_FAILED(svcGetProcessList(&process_count, pids, 0x50))) {
        return false;
    }

    for (s32 i = 0; i < (process_count - 1); i++) {
        if (R_SUCCEEDED(svcDebugActiveProcess(&handle, pids[i])) &&
            R_SUCCEEDED(svcGetDebugEvent(&event_info, handle)) &&
            patch.title_id == event_info.title_id) {
            MemoryInfo mem_info{};
            u64 addr{};
            u32 page_info{};

            for (;;) {
                if (R_FAILED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
                    break;
                }
                addr = mem_info.addr + mem_info.size;

                // if addr=0 then we hit the reserved memory section
                if (!addr) {
                    break;
                }
                // skip memory that we don't want
                if (!mem_info.size || (mem_info.perm & Perm_Rx) != Perm_Rx ||
                    ((mem_info.type & 0xFF) != MemType_CodeStatic)) {
                    continue;
                }

                // todo: the byte pattern can in between 2 READ_BUFFER_SIZE boundries!
                for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE) {
                    const auto actual_size = std::min(READ_BUFFER_SIZE, mem_info.size);
                    if (R_FAILED(svcReadDebugProcessMemory(buffer, handle, mem_info.addr + sz, actual_size))) {
                        // todo: log failed reads!
                        break;
                    } else {
                        patcher(handle, std::span{buffer, actual_size}, mem_info.addr + sz, patch.patterns);
                    }
                }
            }
            svcCloseHandle(handle);
            return true;
        } else if (handle) {
            svcCloseHandle(handle);
            handle = 0;
        }
    }
    return false;
}

// creates a directory, non-recursive!
auto create_dir(const char *path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};
    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }
    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

// same as ini_get but writes out the default value instead
auto ini_load_or_write_default(const char *section, const char *key,
                               long _default, const char *path) -> long {
    if (!ini_haskey(section, key, path)) {
        ini_putl(section, key, _default, path);
        return _default;
    } else {
        return ini_getbool(section, key, _default, path);
    }
}

auto patch_result_to_str(PatchResult result) -> const char * {
    switch (result) {
    case PatchResult::NOT_FOUND:
        return "Unpatched";
    case PatchResult::SKIPPED:
        return "Skipped";
    case PatchResult::DISABLED:
        return "Disabled";
    case PatchResult::PATCHED_FILE:
        return "Patched (file)";
    case PatchResult::PATCHED_SYSPATCH:
        return "Patched (sys-patch)";
    case PatchResult::FAILED_WRITE:
        return "Failed (svcWriteDebugProcessMemory)";
    }
    std::unreachable();
}

void num_2_str(char *&s, u16 num) {
    u16 max_v = 1000;
    if (num > 9) {
        while (max_v >= 10) {
            if (num >= max_v) {
                while (max_v != 1) {
                    *s++ = '0' + (num / max_v);
                    num -= (num / max_v) * max_v;
                    max_v /= 10;
                }
            } else {
                max_v /= 10;
            }
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
}

void ms_2_str(char *s, u32 num) {
    u32 max_v = 100;
    *s++ = '0' + (num / 1000); // add seconds
    num -= (num / 1000) * 1000;
    *s++ = '.';

    while (max_v >= 10) {
        if (num >= max_v) {
            while (max_v != 1) {
                *s++ = '0' + (num / max_v);
                num -= (num / max_v) * max_v;
                max_v /= 10;
            }
        } else {
            *s++ = '0'; // append 0
            max_v /= 10;
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
    *s++ = 's';         // in seconds
}

// eg, 852481 -> 13.2.1
void version_to_str(char *s, u32 ver) {
    for (int i = 0; i < 3; i++) {
        num_2_str(s, (ver >> 16) & 0xFF);
        if (i != 2) {
            *s++ = '.';
        }
        ver <<= 8;
    }
}

} // namespace

int main(int argc, char *argv[]) {
    constexpr auto ini_path = "/config/sys-patch/config.ini";
    constexpr auto log_path = "/config/sys-patch/log.ini";

    create_dir("/config/");
    create_dir("/config/sys-patch/");
    ini_remove(log_path);

    // load options
    const auto patch_emummc = ini_load_or_write_default("options", "patch_emummc", 1, ini_path);

    // load patch toggles
    for (auto &patch : patches) {
        for (auto &p : patch.patterns) {
            p.enabled = ini_load_or_write_default(patch.name, p.patch_name, p.enabled, ini_path);
            if (!p.enabled) {
                p.result = PatchResult::DISABLED;
            }
        }
    }

    const auto emummc = is_emummc();
    bool enable_patching = true;

    // check if we should patch emummc
    if (!patch_emummc && emummc) {
        enable_patching = false;
    }

    // speedtest
    const auto ticks_start = armGetSystemTick();

    if (enable_patching) {
        for (auto &patch : patches) {
            apply_patch(patch);
        }
    }

    const auto ticks_end = armGetSystemTick();
    const auto diff_ns = armTicksToNs(ticks_end) - armTicksToNs(ticks_start);

    {
        // log patch results
        for (auto &patch : patches) {
            for (auto &p : patch.patterns) {
                if (!enable_patching) {
                    p.result = PatchResult::SKIPPED;
                }
                ini_puts(patch.name, p.patch_name, patch_result_to_str(p.result), log_path);
            }
        }

        // fw of the system
        char fw_version[12]{};
        // atmosphere version
        char ams_version[12]{};
        // how long it took to patch
        char patch_time[20]{};

        version_to_str(fw_version, FW_VERSION);
        version_to_str(ams_version, AMS_VERSION);
        ms_2_str(patch_time, diff_ns / 1000ULL / 1000ULL);

        ini_puts("stats", "version", VERSION_WITH_HASH, log_path);
        ini_puts("stats", "build_date", BUILD_DATE, log_path);
        ini_puts("stats", "fw_version", fw_version, log_path);
        ini_puts("stats", "ams_version", ams_version, log_path);
        ini_putl("stats", "is_emummc", emummc, log_path);
        ini_puts("stats", "patch_time", patch_time, log_path);
    }

    // note: sysmod exits here.
    // to keep it running, add a for (;;) loop (remember to sleep!)
    return 0;
}

// libnx stuff goes below
extern "C" {

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Sysmodules will normally only want to use one FS session.
u32 __nx_fs_num_sessions = 1;

// Newlib heap configuration function (makes malloc/free work).
void __libnx_initheap(void) {
    static char inner_heap[INNER_HEAP_SIZE];
    extern char *fake_heap_start;
    extern char *fake_heap_end;

    // Configure the newlib heap.
    fake_heap_start = inner_heap;
    fake_heap_end = inner_heap + sizeof(inner_heap);
}

// Service initialization.
void __appInit(void) {
    Result rc{};

    // Open a service manager session.
    if (R_FAILED(rc = smInitialize()))
        fatalThrow(rc);

    // Retrieve the current version of Horizon OS.
    if (R_SUCCEEDED(rc = setsysInitialize())) {
        SetSysFirmwareVersion fw{};
        if (R_SUCCEEDED(rc = setsysGetFirmwareVersion(&fw))) {
            FW_VERSION = MAKEHOSVERSION(fw.major, fw.minor, fw.micro);
            hosversionSet(FW_VERSION);
        }
        setsysExit();
    }

    // get ams version
    if (R_SUCCEEDED(rc = splInitialize())) {
        u64 v{};
        if (R_SUCCEEDED(rc = splGetConfig((SplConfigItem)65000, &v))) {
            AMS_VERSION = (v >> 40) & 0xFFFFFF;
        }
        splExit();
    }

    if (R_FAILED(rc = fsInitialize()))
        fatalThrow(rc);

    // Add other services you want to use here.
    if (R_FAILED(rc = pmdmntInitialize()))
        fatalThrow(rc);

    // Close the service manager session.
    smExit();
}

// Service deinitialization.
void __appExit(void) {
    pmdmntExit();
    fsExit();
}

} // extern "C"
