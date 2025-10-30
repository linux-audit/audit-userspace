# libev select backend notes

## Build composition
- `libev_la_SOURCES` only lists `ev.c` and `event.c` because `ev.c` directly
  `#include`s the backend implementations such as `ev_select.c`. This means the
  select backend is compiled whenever `ev.c` is built, without needing to list
  the backend sources separately.

## Signal handling and readiness notification
- When a signal arrives, `ev_sighandler()` invokes `ev_feed_signal()`, which
  records the pending signal and calls `evpipe_write()` to wake the loop via the
  self-pipe using the async-signal-safe `write()` system call.
- The select backend copies the tracked fd sets before calling `select()`.
  If `select()` returns with `EINTR`, the backend simply returns to the main
  loop. Because the self-pipe write occurred before the interruption completes,
  the pipe remains readable and will be observed on the next poll iteration,
  ensuring the readiness notification is delivered.
- `select_poll()` also detects `EBADF` and `ENOMEM`, reporting them via
  libev’s error helpers, and it retries interrupted `read()`/`write()` calls to
  drain or signal the pipe, so the loop cannot miss the wakeup due to transient
  EINTR interruptions.
