/* A `bwrap` that makes generic downloaded binaries runnable on NixOS.
 *
 * The bundled Codex CLI sandboxes the commands it runs with bubblewrap. Inside
 * that sandbox it also runs toolchains it downloaded itself — a generic Linux
 * build of git, node, python or pnpm. Those binaries have
 * `/lib64/ld-linux-x86-64.so.2` baked into their ELF header, which does not
 * exist as a real loader on NixOS.
 *
 * NixOS ships a stub at that path (`environment.stub-ld`, on by default) whose
 * only job is to print a helpful error. `nix-ld` is the real solution: put it
 * at the generic loader path and it reads NIX_LD / NIX_LD_LIBRARY_PATH and
 * hands off to the actual store loader.
 *
 * Enabling `programs.nix-ld` system-wide would fix this, but that is a change
 * to the user's configuration, and this package should not require one. So
 * instead we supply our own `bwrap`, placed earlier on PATH than the real one.
 * It inserts three arguments before the sandboxed command:
 *
 *     --ro-bind <nix-ld> <resolved generic loader path>
 *     --setenv NIX_LD <real store loader>
 *     --setenv NIX_LD_LIBRARY_PATH <runtime libraries>
 *
 * and then execs the real bwrap. The bind mount is confined to the sandbox
 * namespace, so nothing outside it is affected.
 *
 * Design notes:
 *   - We insert before the first bare "--", which is where bubblewrap stops
 *     reading its own options and starts reading the command to run.
 *   - If there is no "--", we append at the end; bwrap will reject a malformed
 *     invocation on its own terms rather than ours.
 *   - If the generic loader path cannot be resolved, we exec the real bwrap
 *     with the arguments untouched. Losing the generic-runtime bridge is a
 *     degraded feature; breaking the sandbox would be a defect.
 *   - We never add, remove or reorder any other argument.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef REAL_BWRAP
#error "REAL_BWRAP must be defined at compile time"
#endif
#ifndef NIX_LD_PATH
#error "NIX_LD_PATH must be defined at compile time"
#endif
#ifndef NIX_LD_TARGET
#error "NIX_LD_TARGET must be defined at compile time"
#endif
#ifndef NIX_LD_LIBRARY_PATH_VALUE
#error "NIX_LD_LIBRARY_PATH_VALUE must be defined at compile time"
#endif
#ifndef GENERIC_INTERPRETER
#error "GENERIC_INTERPRETER must be defined at compile time"
#endif

/* Where the shim writes its rewritten argv instead of exec'ing, so tests can
 * assert the exact argument vector. Only honoured when set. */
static const char *kTraceEnv = "CHATGPT_BWRAP_SHIM_TRACE";

int main(int argc, char **argv) {
    const char *trace = getenv(kTraceEnv);

    /* Resolve the generic loader path. On NixOS this is normally a symlink
     * into the store provided by environment.stub-ld. We bind over whatever it
     * actually resolves to, so the target inside the sandbox matches what the
     * downloaded binary's ELF header will ask for. */
    /* realpath(x, NULL) allocates, which avoids depending on PATH_MAX. */
    char *resolved = realpath(GENERIC_INTERPRETER, NULL);
    const char *bind_target = NULL;
    if (resolved != NULL) {
        bind_target = resolved;
    } else if (access(GENERIC_INTERPRETER, F_OK) == 0) {
        bind_target = GENERIC_INTERPRETER;
    }

    if (bind_target == NULL) {
        /* No generic loader on this host. Run the real bwrap unchanged: the
         * sandbox still works, only the downloaded-toolchain bridge is absent. */
        if (trace != NULL) {
            FILE *out = fopen(trace, "w");
            if (out != NULL) {
                fprintf(out, "passthrough\n");
                for (int i = 1; i < argc; i++) fprintf(out, "%s\n", argv[i]);
                fclose(out);
            }
            return 0;
        }
        execv(REAL_BWRAP, argv);
        fprintf(stderr, "chatgpt bwrap shim: cannot exec %s: %s\n",
                REAL_BWRAP, strerror(errno));
        return 127;
    }

    /* Insert immediately after argv[0], before any caller-supplied option.
     *
     * The obvious alternative -- scan for the first bare "--" and insert
     * before it -- is wrong, because "--" is not necessarily the separator.
     * Several bwrap options take an arbitrary value, so `bwrap --setenv FOO --
     * -- /bin/true` has "--" as the *value* of --setenv, and splicing there
     * would corrupt the command. Correctly identifying the separator would
     * mean reimplementing bwrap's option table and keeping it in sync.
     *
     * Inserting at the front needs no parsing and is unambiguous. Our
     * arguments are ordinary bwrap options, and because they come first, a
     * caller that deliberately binds over the same path later still wins --
     * bwrap applies binds in order. */
    const int split = 1;

    /* The arguments we splice in, in order. */
    char *const inserted[] = {
        "--ro-bind", (char *)NIX_LD_PATH, (char *)bind_target,
        "--setenv", "NIX_LD", (char *)NIX_LD_TARGET,
        "--setenv", "NIX_LD_LIBRARY_PATH", (char *)NIX_LD_LIBRARY_PATH_VALUE,
    };
    const int kInserted = (int)(sizeof(inserted) / sizeof(inserted[0]));

    char **out = calloc((size_t)argc + (size_t)kInserted + 1, sizeof(char *));
    if (out == NULL) {
        fprintf(stderr, "chatgpt bwrap shim: out of memory\n");
        return 127;
    }

    int n = 0;
    for (int i = 0; i < split; i++) out[n++] = argv[i];
    for (int i = 0; i < kInserted; i++) out[n++] = inserted[i];
    for (int i = split; i < argc; i++) out[n++] = argv[i];
    out[n] = NULL;

    if (trace != NULL) {
        FILE *out_file = fopen(trace, "w");
        if (out_file == NULL) {
            fprintf(stderr, "chatgpt bwrap shim: cannot write trace: %s\n",
                    strerror(errno));
            return 127;
        }
        fprintf(out_file, "rewritten\n");
        for (int i = 1; i < n; i++) fprintf(out_file, "%s\n", out[i]);
        fclose(out_file);
        return 0;
    }

    execv(REAL_BWRAP, out);
    fprintf(stderr, "chatgpt bwrap shim: cannot exec %s: %s\n",
            REAL_BWRAP, strerror(errno));
    return 127;
}
