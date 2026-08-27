/* A `bwrap` that makes generic downloaded binaries runnable on NixOS.
 *
 * The bundled Codex CLI sandboxes the commands it runs with bubblewrap. Inside
 * that sandbox it also runs toolchains it downloaded itself — a generic Linux
 * build of git, node, python or pnpm. Those binaries have
 * `/lib64/ld-linux-x86-64.so.2` baked into their ELF header.
 *
 * On NixOS that path is not glibc's loader. By default it is `environment.
 * stub-ld`: a static stub whose entire behaviour is to print "Could not start
 * dynamically linked executable" and exit 127.
 *
 * Enabling `programs.nix-ld` system-wide would replace that stub, but that is a
 * change to the user's configuration and this package should not require one.
 * So we supply our own `bwrap`, earlier on PATH than the real one, which
 * puts `nix-ld` at the loader path *inside the sandbox* and tells it which
 * store loader and libraries to use, then execs the real bwrap.
 *
 * What gets injected, and why the bind target is the resolved path
 * ----------------------------------------------------------------
 *
 * `--setenv NIX_LD` alone is not enough. NixOS's default `environment.stub-ld`
 * is not nix-ld: it is a static stub whose entire behaviour is to print
 * "Could not start dynamically linked executable" and exit 127. It never
 * consults NIX_LD. So the loader at the generic path has to be replaced, not
 * merely configured.
 *
 * The bind destination is the *resolved* path, not the generic path itself.
 * Measured against bubblewrap 0.11.2: binding onto `/lib64/ld-linux-x86-64.so.2`
 * after a `--ro-bind / /` fails with "Can't create file ... No such file or
 * directory", because that path is a symlink on NixOS and bwrap will not bind
 * over a symlink. Binding onto what it resolves to — an ordinary file in the
 * store — succeeds, and the symlink then leads to our nix-ld.
 *
 * Ordering is what makes this work at all. Placed before the caller's mounts,
 * a later `--ro-bind / /` simply covers the bind and it has no effect;
 * verified directly. Placed after them, it takes effect.
 *
 * Where the arguments go
 * ----------------------
 *
 * They are spliced after ALL of the caller's options, immediately before the
 * command. That matters: a caller's `--clearenv` or its own `--setenv NIX_LD`
 * appearing later would otherwise override ours.
 *
 * Finding that point requires actually parsing bwrap's option grammar. Looking
 * for the first bare "--" is wrong, because several options take arbitrary
 * values and `bwrap --setenv FOO -- -- cmd` has "--" as the value of --setenv.
 * The table below is bubblewrap 0.11.2's complete option set with each option's
 * argument count.
 *
 * Anything the table does not cover — an unrecognised option, a truncated
 * option, or `--args FD`, whose options we cannot see because they come from a
 * file descriptor — means we cannot locate the splice point with certainty. In
 * that case we exec the real bwrap with the argument vector untouched. Losing
 * the generic-runtime bridge degrades a feature; guessing wrong would corrupt
 * the sandbox.
 */

#include <errno.h>
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
#ifndef GENERIC_INTERPRETER
#error "GENERIC_INTERPRETER must be defined at compile time"
#endif
#ifndef NIX_LD_LIBRARY_PATH_VALUE
#error "NIX_LD_LIBRARY_PATH_VALUE must be defined at compile time"
#endif

struct bwrap_option {
    const char *name;
    int arity;
};

/* bubblewrap 0.11.2, `bwrap --help`, in order. */
static const struct bwrap_option kOptions[] = {
    {"--help", 0},
    {"--version", 0},
    {"--args", 1},                  /* see kUnknown handling below */
    {"--argv0", 1},
    {"--level-prefix", 0},
    {"--unshare-all", 0},
    {"--share-net", 0},
    {"--unshare-user", 0},
    {"--unshare-user-try", 0},
    {"--unshare-ipc", 0},
    {"--unshare-pid", 0},
    {"--unshare-net", 0},
    {"--unshare-uts", 0},
    {"--unshare-cgroup", 0},
    {"--unshare-cgroup-try", 0},
    {"--userns", 1},
    {"--userns2", 1},
    {"--disable-userns", 0},
    {"--assert-userns-disabled", 0},
    {"--pidns", 1},
    {"--uid", 1},
    {"--gid", 1},
    {"--hostname", 1},
    {"--chdir", 1},
    {"--clearenv", 0},
    {"--setenv", 2},
    {"--unsetenv", 1},
    {"--lock-file", 1},
    {"--sync-fd", 1},
    {"--bind", 2},
    {"--bind-try", 2},
    {"--dev-bind", 2},
    {"--dev-bind-try", 2},
    {"--ro-bind", 2},
    {"--ro-bind-try", 2},
    {"--bind-fd", 2},
    {"--ro-bind-fd", 2},
    {"--remount-ro", 1},
    {"--overlay-src", 1},
    {"--overlay", 3},
    {"--tmp-overlay", 1},
    {"--ro-overlay", 1},
    {"--exec-label", 1},
    {"--file-label", 1},
    {"--proc", 1},
    {"--dev", 1},
    {"--tmpfs", 1},
    {"--mqueue", 1},
    {"--dir", 1},
    {"--file", 2},
    {"--bind-data", 2},
    {"--ro-bind-data", 2},
    {"--symlink", 2},
    {"--seccomp", 1},
    {"--add-seccomp-fd", 1},
    {"--block-fd", 1},
    {"--userns-block-fd", 1},
    {"--info-fd", 1},
    {"--json-status-fd", 1},
    {"--new-session", 0},
    {"--die-with-parent", 0},
    {"--as-pid-1", 0},
    {"--cap-add", 1},
    {"--cap-drop", 1},
    {"--perms", 1},
    {"--size", 1},
    {"--chmod", 2},
};

static const int kOptionCount =
    (int)(sizeof(kOptions) / sizeof(kOptions[0]));

/* Sentinel: the splice point cannot be determined from argv alone. */
#define SPLICE_UNKNOWN (-1)

/* Return the index at which our own options should be inserted: the position
 * of the "--" terminator, or of the first non-option word, whichever comes
 * first. SPLICE_UNKNOWN if the vector cannot be parsed with certainty. */
static int find_splice_point(int argc, char **argv) {
    int i = 1;
    while (i < argc) {
        const char *arg = argv[i];

        if (strcmp(arg, "--") == 0) {
            return i;
        }
        if (arg[0] != '-') {
            /* First word that is not an option: the command. */
            return i;
        }

        /* `--args FD` supplies further options from a file descriptor. Those
         * options are invisible here, so any splice point we computed could
         * land in the middle of them. */
        if (strcmp(arg, "--args") == 0) {
            return SPLICE_UNKNOWN;
        }

        int arity = SPLICE_UNKNOWN;
        for (int k = 0; k < kOptionCount; k++) {
            if (strcmp(arg, kOptions[k].name) == 0) {
                arity = kOptions[k].arity;
                break;
            }
        }
        if (arity == SPLICE_UNKNOWN) {
            /* An option this build of bwrap understands and we do not. */
            return SPLICE_UNKNOWN;
        }
        if (i + arity >= argc) {
            /* Truncated: bwrap will reject it. Do not rewrite it first. */
            return SPLICE_UNKNOWN;
        }
        i += 1 + arity;
    }
    /* Options only, no command. bwrap will complain; leave it to do so. */
    return SPLICE_UNKNOWN;
}

int main(int argc, char **argv) {
    const int splice = find_splice_point(argc, argv);

    if (splice == SPLICE_UNKNOWN) {
        execv(REAL_BWRAP, argv);
        fprintf(stderr, "chatgpt bwrap shim: cannot exec %s: %s\n",
                REAL_BWRAP, strerror(errno));
        return 127;
    }

    /* realpath(x, NULL) allocates, avoiding any dependency on PATH_MAX. A
     * failure here means the host has no loader at the generic path at all,
     * in which case there is nothing to bind over; the environment variables
     * are still worth setting for a host that does provide a real nix-ld. */
    char *resolved = realpath(GENERIC_INTERPRETER, NULL);

    char *inserted[9];
    int kInserted = 0;
    if (resolved != NULL) {
        inserted[kInserted++] = (char *)"--ro-bind";
        inserted[kInserted++] = (char *)NIX_LD_PATH;
        inserted[kInserted++] = resolved;
    }
    inserted[kInserted++] = (char *)"--setenv";
    inserted[kInserted++] = (char *)"NIX_LD";
    inserted[kInserted++] = (char *)NIX_LD_TARGET;
    inserted[kInserted++] = (char *)"--setenv";
    inserted[kInserted++] = (char *)"NIX_LD_LIBRARY_PATH";
    inserted[kInserted++] = (char *)NIX_LD_LIBRARY_PATH_VALUE;

    char **out = calloc((size_t)argc + (size_t)kInserted + 1, sizeof(char *));
    if (out == NULL) {
        fprintf(stderr, "chatgpt bwrap shim: out of memory\n");
        return 127;
    }

    int n = 0;
    for (int i = 0; i < splice; i++) out[n++] = argv[i];
    for (int i = 0; i < kInserted; i++) out[n++] = inserted[i];
    for (int i = splice; i < argc; i++) out[n++] = argv[i];
    out[n] = NULL;

#ifdef SHIM_TRACE_ENV
    /* Test-only build. The production shim has no way to be diverted by the
     * environment: an inherited variable must never be able to suppress the
     * sandbox or write to a file of the caller's choosing. */
    {
        const char *trace = getenv(SHIM_TRACE_ENV);
        if (trace != NULL) {
            FILE *fh = fopen(trace, "w");
            if (fh == NULL) {
                fprintf(stderr, "shim trace: %s: %s\n", trace, strerror(errno));
                return 127;
            }
            for (int i = 1; i < n; i++) fprintf(fh, "%s\n", out[i]);
            fclose(fh);
            return 0;
        }
    }
#endif

    execv(REAL_BWRAP, out);
    fprintf(stderr, "chatgpt bwrap shim: cannot exec %s: %s\n",
            REAL_BWRAP, strerror(errno));
    return 127;
}
