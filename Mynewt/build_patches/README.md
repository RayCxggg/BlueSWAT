# Mynewt build patches

`newt build peripheral` against the SHAs pinned in `.gitmodules` requires
two small fixes in `apache-mynewt-core` to be compatible with current
host toolchains (newer newlib + GCC 13). The submodule pin is upstream
and not maintained here, so the fixes ride alongside the main repo as
patch files instead of being committed into the submodule.

## How to apply

```sh
cd Mynewt/repos/apache-mynewt-core
git apply ../../build_patches/0001-apache-mynewt-core-newer-toolchain-fixes.patch
```

## What the patch does

1. **`encoding/tinycbor/src/cborpretty.c` + `cbortojson.c`** — defines
   `PRIu64` / `PRIx64` fallbacks. Newer newlib gates these macros on
   `__int64_t_defined`, which Mynewt's embedded build doesn't get;
   without the fallbacks the compiler treats `"%" PRIu64` as a stray
   `%` and `-Werror=format=` fails the build.

2. **`hw/mcu/nordic/nrf52xxx/src/hal_timer.c`** — initialises
   `entry = NULL` to silence a GCC 13 `-Wmaybe-uninitialized` false
   positive in `hal_timer_stop`. The path that reads `entry` is gated
   by `reset_ocmp`, which is only set in the same branch that assigns
   `entry`, but GCC 13's stricter flow analysis can't see that.

Neither fix changes runtime behavior; they're build-system hygiene
that newer toolchains require.
