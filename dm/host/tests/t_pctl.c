// Resolve the real force-registration entries: a missing/misspelled hook must fail.
// No guest modules, IPC session or system applet are available in this test.
#include "../hle_misc.c"
#include <mach-o/getsect.h>

static int unexpected, checks, fails;
void *guest_sym(const char *name) { (void)name; unexpected++; return NULL; }
module_t *module_of(const void *p) { (void)p; unexpected++; return NULL; }
void hle_bind_system_event(void *g, int autoclear) { (void)g; (void)autoclear; unexpected++; }
extern const struct mach_header_64 _mh_execute_header;
#define CHECK(c, msg) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL: %s\n", msg); } } while (0)
static void *hook(const char *name) {
    unsigned long bytes = 0;
    const hle_force_ent *entries = (const hle_force_ent *)getsectiondata(&_mh_execute_header, "__DATA", "swforce", &bytes);
    void *fn = NULL; unsigned count = 0;
    for (size_t i = 0; entries && i < bytes / sizeof *entries; i++) {
        if (strcmp(entries[i].name, name)) continue;
        count++; fn = entries[i].fn;
        CHECK(entries[i].why && entries[i].why[0], "takeover has a reason");
    }
    CHECK(count == 1 && fn, name);
    return count == 1 ? fn : NULL;
}
int main(void) {
    // Switch bool parameters are widened as required by hle.h. Return values
    // are canonical booleans in w0, not nn::Result success/failure codes.
    unsigned (*check)(unsigned) = hook("_ZN2nn4pctl32CheckFreeCommunicationPermissionEb");
    unsigned (*begin)(unsigned) = hook("_ZN2nn4pctl25TryBeginFreeCommunicationEb");
    unsigned (*available)(void) = hook("_ZN2nn4pctl28IsFreeCommunicationAvailableEv");
    void (*end)(void) = hook("_ZN2nn4pctl20EndFreeCommunicationEv");
    unsigned (*stereo)(unsigned) = hook("_ZN2nn4pctl27CheckStereoVisionPermissionEb");
    const unsigned args[] = {0, 1, 0x100, 0x101, ~0u};
    if (available) CHECK(available() == 0, "communication unavailable before permission queries");
    for (size_t i = 0; i < sizeof args / sizeof *args; i++) {
        if (check) CHECK(check(args[i]) == 0, "permission query denies communication, with or without UI requested");
        if (begin) CHECK(begin(args[i]) == 0, "begin agrees with the offline permission policy");
        // Positive control: denying communication must not deny unrelated 3D permission.
        if (stereo) CHECK(stereo(args[i]) == 1, "stereo permission remains allowed");
        if (end) end();
        if (check) CHECK(check(args[i]) == 0, "ending communication does not grant permission");
        if (available) CHECK(available() == 0, "permission checks do not make communication available");
    }
    CHECK(unexpected == 0, "permission path needs no guest lookup or event binding");
    printf("pctl offline policy: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
