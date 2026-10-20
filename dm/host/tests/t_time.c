// Host-backed user clocks: exercise the registered ABI without a guest SDK or IPC.
#include "../hle_time.c"
#include <mach-o/getsect.h>

module_t g_mod[MAX_MOD]; int g_nmod;
void *module_sym(module_t *m, const char *name) { (void)m; (void)name; return NULL; }
extern const struct mach_header_64 _mh_execute_header;

static int checks, fails;
#define CHECK(c, msg) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL: %s\n", msg); } } while (0)
static void *hook(const char *name) {
    unsigned long bytes = 0;
    const hle_force_ent *entries = (const hle_force_ent *)getsectiondata(&_mh_execute_header, "__DATA", "swforce", &bytes);
    for (size_t i = 0; entries && i < bytes / sizeof *entries; i++)
        if (!strcmp(entries[i].name, name)) return entries[i].fn;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "fixed") && strcmp(argv[1], "live"))) {
        fprintf(stderr, "usage: t_time fixed|live\n"); return 2;
    }
    int fixed = !strcmp(argv[1], "fixed");
    if (fixed) setenv("DM_FIXED_TIME", "1700000000", 1); else unsetenv("DM_FIXED_TIME");
    // Independently resolve exact guest symbols: an omitted/misspelled hook must fail,
    // rather than accidentally testing a static helper the loader cannot reach.
    void (*adjust)(void) = hook("_ZN2nn4time25AdjustableUserSystemClock6AdjustEv");
    Result (*current)(int64_t *) = hook("_ZN2nn4time25AdjustableUserSystemClock14GetCurrentTimeEPNS0_9PosixTimeE");
    CHECK(adjust != NULL, "Adjust registered under the exact SDK symbol");
    CHECK(current != NULL, "GetCurrentTime registered under the exact SDK symbol");
    CHECK(h_time_Initialize() == RES_OK && h_time_IsInitialized(), "host time initializes without a guest module");
    if (adjust && current) {
        for (int i = 0; i < 3; i++) {
            struct { uint64_t before; int64_t value; uint64_t after; } out = {0x11223344, -1, 0x55667788};
            time_t lo = time(NULL);
            adjust();
            CHECK(current(&out.value) == RES_OK, "adjustable read returns a successful Result");
            time_t hi = time(NULL);
            CHECK(out.before == 0x11223344 && out.after == 0x55667788, "read writes only the 8-byte PosixTime output");
            if (fixed) {
                int64_t standard = -1;
                CHECK(out.value == 1700000000, "adjustable read honors DM_FIXED_TIME after repeated Adjust");
                CHECK(h_time_GetCurrentTime(&standard) == RES_OK && standard == out.value, "standard and adjustable clocks share the fixed-time policy");
            } else {
                CHECK(out.value >= lo && out.value <= hi, "without DM_FIXED_TIME the adjustable clock follows host wall time");
            }
        }
    }
    printf("time (%s): %d checks, %d failed\n", argv[1], checks, fails);
    return fails != 0;
}
