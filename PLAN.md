# PLAN.md — multi-monitor follow-the-cursor: redesign

Tracked plan for cleaning up the follow-the-cursor feature.

**Rationale (verified on this box):** on Cosmic (`cosmic-comp`), an absolute uinput device's `EV_ABS`
range is mapped onto the *single output the cursor currently occupies*, not across the virtual
desktop. KDE/GNOME map it across the virtual desktop. So each monitor behaves as an isolated
single-monitor case, and stock reframe's per-monitor coordinate mapping already works unchanged; the
only thing genuinely needed is cross-monitor cursor *relocation*. This plan strips the feature back
to that, so it stops altering stock config semantics.

## Action items

### Config keys
- [ ] **Add a boolean toggle `relocate` (default `false`)** — the feature on/off switch, following
      reframe's bare-predicate boolean convention (`resize`/`cursor`/`wakeup`; NOT `relocate-on`).
      `false` → relocation disabled → stock behaviour. New rf-config boolean getter (copy an existing
      one). `on_input_msg` does nothing unless `relocate` is true.
- [ ] **Rename `position-x` → `relocate-origin-x`** (same value: this monitor's real desktop X /
      top-left origin; same rf-config getter, renamed). With the boolean owning on/off, this is a
      **pure coordinate** — no sentinel — so any value works, **including negative** (a monitor left of
      the origin when the primary isn't leftmost). It's distinct from `monitor-x` (the mapping
      coordinate) via the `relocate-` prefix + the comment; relocation is its only consumer:
  - [ ] Burst **direction**: `dir = relocate_origin_x > owner_x ? 1 : -1`.
  - [ ] Cursor-**owner identity**: store `relocate-origin-x` in the owner file (unique per monitor).
- [ ] **`example.conf` ships the feature OFF**, with these two comments (locked):
      ```
      # Set to `true` on compositors that show the pointer on one monitor at a time
      # (e.g. Cosmic) to make the cursor follow the stream you drive. Needs relocate-origin-x.
      relocate=false
      # This monitor's real desktop X (e.g. 1920), used only when relocate=true.
      # monitor-x is 0 on these compositors, so relocation reads the position here.
      relocate-origin-x=
      ```
- [ ] **Do not set `desktop-width`/`monitor-x` at all — use the stock single-monitor defaults.** On
      Cosmic each output is mapped standalone, so `monitor-x=0` + `desktop-width` unset (→ auto-fills
      `frame_width`) already yields correct per-monitor positioning with **zero code change**. This
      leaves both keys' stock meanings intact and makes the `desktop-width` redefinition complaint
      disappear by simply not writing the misleading value. No renormalization, no flag, no new key.

### Cursor ownership (portability) — drop the cursor-plane dependency (his `main.c:515`)
- [ ] **Delete the `cursor_owner_publish(this)` call (and its comment) from `on_frame_msg`.** Leave
      the stock cursor-plane *capture* (`cursor=true`) above it untouched — only the feature's
      ownership inference goes. Ownership then comes purely from the input path: `on_input_msg`
      already claims after relocating, so it self-maintains after the first input.
- [ ] **Seed the unknown-owner (first-input) case.** With the plane gone, nothing initializes the
      owner file, so `on_input_msg` must also relocate when `cursor_owner_read()` *fails* (not only
      when `owner != me`). On unknown owner: burst toward THIS monitor's edge, claim, then inject —
      the over-travel clamps the cursor home from anywhere, so it's safe even if it was already here.
- [ ] **Learn the layout from sibling configs (only for the unknown-owner burst direction).** At
      startup, when `relocate=true`: glob `<dir>/*.conf` (dir = `dirname` of this streamer's
      `--config`; `.bak-*` backups don't match `*.conf`), read `relocate-origin-x` from each where
      `relocate=true`, compute min/max. Precompute `unknown_dir`: `relocate-origin-x == min → -1`
      (leftmost → burst left), `== max → +1` (rightmost → burst right). A middle monitor (N>2) is the
      known-unsupported case → default to the nearer extreme + `g_warning`.
  - [ ] Known owner keeps the existing rule: `dir = relocate_origin_x > owner_x ? 1 : -1`.
  - [ ] Sandbox is fine — the streamer unit's `ProtectSystem=strict` leaves `/etc` readable.

### Maintainer's code & comments (this PR is a redo — treat his comments as documentation)
- [ ] **Audit done.** Stock comments were removed in exactly ONE place — `setup_uinput`. The feature
      also added ~66 comment lines in `main.c`, 16 in `example.conf`, 5 in `rf-config.c`. Restore
      these four lines VERBATIM on the `ufd` (absolute) device:
      ```
      // It seems trying to be both touchscreen and mouse leads into bugs,
      // anyway, we only send absolute coordinates.
      // ioctl_must(this->ufd, UI_SET_RELBIT, REL_X);
      // ioctl_must(this->ufd, UI_SET_RELBIT, REL_Y);
      ```
- [ ] **Append, don't replace.** After his restored lines, add ONE terse note that the relative burst
      now lives on the separate `ufd_rel` device (so the reader sees why `ufd` stays absolute-only and
      where `REL_X/Y` went). Leave his wording untouched.
- [ ] **Trim our comments to terse.** Cut the ~66-line `main.c` comment bloat to the minimum that
      explains the Cosmic behaviour (cursor-owner file, relocation burst, the two devices). Concise
      and clear; append-only relative to any stock comment.

### Scope / known limitation (document it; don't pretend it's solved)
- [ ] State plainly that relocation reliably lands only on the **outermost** monitors; a 3+ monitor
      layout with a *middle* target is unsolved (Cosmic mishandles precise large relative deltas — the
      reason the burst over-travels and clamps). Put it in two places: a one-line note in the
      `example.conf` `relocate` block, and a short comment at `cursor_relocate`.
- [ ] Cross-ref: the unknown-owner path already `g_warning`s when this monitor is a middle one (see
      the cursor-ownership spec), so the limit is both documented and surfaced at runtime.

### Verify (on the 2-monitor Cosmic box, using the proven DRM cursor-plane oracle)
- [ ] Build warning-clean: `meson setup build -Ddebug=true && meson compile -C build` (warning_level 3).
- [ ] Install with a backup of the running binary; set `/etc/reframe/{DP-1,DP-3}.conf` to stock
      positioning (NO `desktop-width`/`monitor-x` overrides) + `relocate=true`, `relocate-origin-x=0`
      (DP-1) / `=1920` (DP-3).
- [ ] Oracle = `/sys/kernel/debug/dri/0/state` (the 256×256 cursor plane's CRTC + position;
      crtc-0=DP-1, crtc-1=DP-3) via the `read_cursor.py` helper; drive each stream with `vncdotool`.
  - [ ] Positioning: sweep each monitor's VNC view across its width → cursor tracks within that
        monitor (correct CRTC, x ∝ VNC x).
  - [ ] Relocation/follow: cursor on DP-1, then drive DP-3's view → cursor crosses to crtc-1 and
        positions correctly (and the reverse).
  - [ ] First-input/unknown: `systemctl restart` reframe (clears `/run/reframe/cursor-owner`), then
        drive one monitor cold → relocation still aims correctly (validates the sibling-config direction).
  - [ ] Feature OFF: `relocate=false` → no relocation, stock behaviour (regression check).
- [ ] Restore the production binary + configs afterward; log the install/deploy in the workspace
      changelog (`/mnt/TOCC_SHARED/home/claude/ClaudeITChanges.log`), per repo CLAUDE.md.
