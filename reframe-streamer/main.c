#include <fcntl.h>
#include <sys/file.h>
#include <stdint.h>
#include <stdbool.h>
#include <locale.h>
#include <glib.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gio/gunixfdmessage.h>
#include <gio/gunixsocketaddress.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#include <libdrm/drm_fourcc.h>
#include <linux/uinput.h>

#include "config.h"
#include "rf-common.h"
#include "rf-config.h"

#ifdef HAVE_LIBSYSTEMD
#	include <systemd/sd-daemon.h>
#endif

#define WAKEUP_MAX_EVENTS 4

// Shared file (named cursor-owner, alongside the socket) recording which monitor
// currently holds the system cursor. It holds one int: the relocate-origin-x of
// that monitor. The per-monitor streamers read/write it under an exclusive flock.
// Ownership is tracked from the input path (last monitor to receive a pointer
// event); on_input_msg reads it to decide whether to relocate onto this monitor.

// Cross-monitor relocation is emitted as a BURST of small relative steps, not
// one giant delta: COSMIC/libinput ignores (or caps) a single huge REL_X, but
// honors many small steps spaced a few ms apart (empirically confirmed).
#define RELOCATE_STEP_PX 40 // px per relative step.
// Anchor over-travel: 120 * 40 = 4800 raw px, and with the measured ~2x gain
// that is ~9600px effective — larger than any desktop, so the cursor always
// reaches (and clamps at) the target wall no matter which monitor it started on.
#define RELOCATE_ANCHOR_STEPS 120
// Spacing between steps; libinput needs this gap to honor each motion.
#define RELOCATE_STEP_DELAY_US 3000
// Measured relative-motion gain on cosmic-comp: landed desktop px per injected
// raw px is a flat ~1.97x — velocity-independent and linear in displacement (see
// CHANGELOG.untracked.md, 2026-06-30). Sizes the calibrated middle-monitor burst;
// the half-monitor landing tolerance makes this rough constant robust.
#define RELOCATE_GAIN 1.97

// clang-format off
#define ioctl_must(...)                                                         \
	G_STMT_START {                                                           \
		int e;                                                           \
		if ((e = ioctl(__VA_ARGS__)))                                    \
			g_error("Input: Failed to call ioctl() at line %d: %d.", \
				__LINE__,                                        \
				e);                                              \
	} G_STMT_END
#define ioctl_may(...)                                                          \
	G_STMT_START {                                                           \
		int e;                                                           \
		if ((e = ioctl(__VA_ARGS__)))                                    \
			g_warning(                                               \
				"Input: Failed to call ioctl() at line %d: %d.", \
				__LINE__,                                        \
				e                                                \
			);                                                       \
	} G_STMT_END

#define write_may(fd, buf, count)                                                                              \
	G_STMT_START {                                                                                          \
		size_t e = write((fd), (buf), (count));                                                        \
		if (e != (count))                                                                               \
			g_warning(                                                                              \
				"Input: Failed to write %ld bytes to %d at line %d, actually wrote %ld bytes.", \
				(count),                                                                        \
				(fd),                                                                           \
				__LINE__,                                                                       \
				e                                                                               \
			);                                                                                      \
	} G_STMT_END
// clang-format on

// Relocation anchor strategy for this monitor, derived from the layout. An edge
// monitor over-travels to its own outer wall and clamps inside itself; a middle
// monitor has no wall of its own, so it anchors at the left wall then fires a
// calibrated burst right to land within its span.
enum relocate_pos { RELOCATE_LEFT_EDGE, RELOCATE_RIGHT_EDGE, RELOCATE_MIDDLE };

struct this {
	RfConfig *config;
	GSocketConnection *connection;
	// Cross-monitor cursor relocation (config key "relocate", default off).
	bool relocate;
	// This monitor's real desktop X (config key "relocate-origin-x"): owner
	// identity + calibrated-burst target. Separate from monitor-x.
	int relocate_origin_x;
	// Relocation geometry, precomputed from sibling configs + DRM (read only when
	// relocate is set): kind selects the anchor strategy; left_wall_x is the min
	// relocate-origin-x across participating monitors (the middle-monitor anchor);
	// width is this monitor's pixel width (the calibrated-burst target center).
	enum relocate_pos kind;
	int left_wall_x;
	int width;
	// Live monitor layout pushed from the session (RF_MSG_TYPE_LAYOUT), NULL
	// until the first push. When present it supersedes the config-derived
	// geometry above and drives 2-D relocation; when absent (login screen /
	// headless) relocation falls back to the config sibling-scan + 1-D burst.
	struct rf_monitor *layout;
	unsigned int layout_n;
	// Directory of this streamer's config, for reading sibling configs.
	char *config_dir;
	// Path of the shared cursor-owner file (alongside the socket).
	char *owner_path;
	char *card_path;
	char *connector_name;
	int cfd;
	uint32_t crtc_id;
	uint32_t primary_id;
	bool cursor;
	uint32_t cursor_id;
	int ufd;
	// Separate relative-only pointer device, used only for the cross-monitor
	// cursor relocation burst (see setup_uinput / issue #36).
	int ufd_rel;
	bool wakeup;
	bool skip_auth;
};

static int auth_pid(struct this *this, pid_t pid, const char *target)
{
	if (this->skip_auth)
		return 0;

	g_autoptr(GError) error = NULL;
	g_autofree char *proc_exe = g_strdup_printf(
		G_DIR_SEPARATOR_S "proc" G_DIR_SEPARATOR_S
				  "%d" G_DIR_SEPARATOR_S "exe",
		pid
	);
	g_autofree char *bin = g_file_read_link(proc_exe, &error);
	if (bin == NULL) {
		g_warning(
			"Auth: Failed to read link of %s: %s.",
			proc_exe,
			error->message
		);
		return -1;
	}
	g_debug("Auth: Authenticating process executable binary %s.", bin);
	if (g_strcmp0(bin, target) != 0)
		return -2;
	return 0;
}

static ssize_t send_auth_msg(struct this *this, pid_t pid, bool ok)
{
	ssize_t ret = 0;
	g_autoptr(GError) error = NULL;
	GOutputStream *os =
		g_io_stream_get_output_stream(G_IO_STREAM(this->connection));

	ret = rf_send_header(this->connection, RF_MSG_TYPE_AUTH, 1, &error);
	if (ret <= 0)
		goto out;
	struct rf_auth auth;
	auth.pid = pid;
	auth.ok = ok;
	ret = g_output_stream_write(os, &auth, sizeof(auth), NULL, &error);

out:
	if (ret < 0)
		g_warning(
			"Auth: Failed to send auth message: %s.", error->message
		);
	else if (ret > 0)
		g_debug("Auth: Sent auth message for PID %d with result %s.",
			auth.pid,
			auth.ok ? "OK" : "not OK");
	return ret;
}

static ssize_t on_auth_msg(struct this *this)
{
	ssize_t ret = 0;
	size_t length = 0;
	g_autoptr(GError) error = NULL;
	GInputStream *is =
		g_io_stream_get_input_stream(G_IO_STREAM(this->connection));

	ret = g_input_stream_read(is, &length, sizeof(length), NULL, &error);
	if (ret <= 0 || length != 1)
		goto out;
	pid_t pid = -1;
	ret = g_input_stream_read(is, &pid, sizeof(pid), NULL, &error);
	if (ret <= 0 || pid < 0)
		goto out;

	g_debug("Auth: Received auth message for PID %d.", pid);
	bool ok = auth_pid(
			  this, pid, BINDIR G_DIR_SEPARATOR_S "reframe-session"
		  ) == 0;
	return send_auth_msg(this, pid, ok);

out:
	if (ret < 0)
		g_warning(
			"Auth: Failed to receive auth message: %s.",
			error->message
		);
	return ret;
}

// You need to explicitly cast the type of returned value.
static uint64_t get_plane_prop(
	int cfd,
	uint32_t plane_id,
	const char *name,
	uint64_t default_value
)
{
	uint64_t value = default_value;
	drmModeObjectProperties *props = drmModeObjectGetProperties(
		cfd, plane_id, DRM_MODE_OBJECT_PLANE
	);
	if (props == NULL)
		return value;
	for (size_t i = 0; i < props->count_props; ++i) {
		drmModePropertyRes *prop =
			drmModeGetProperty(cfd, props->props[i]);
		if (prop == NULL)
			continue;
		if (g_strcmp0(prop->name, name) == 0)
			value = props->prop_values[i];
		drmModeFreeProperty(prop);
	}
	drmModeFreeObjectProperties(props);
	return value;
}

// We have to get plane via ID every frame to get the newest framebuffer.
static uint32_t get_plane_id(int cfd, uint32_t crtc_id, uint32_t type)
{
	uint32_t plane_id = 0;
	drmModePlaneRes *pres = drmModeGetPlaneResources(cfd);
	if (pres == NULL) {
		g_warning("DRM: Failed to get plane resources.");
		return 0;
	}
	g_debug("DRM: Finding plane of type %s and CRTC ID %u.",
		rf_plane_type(type),
		crtc_id);
	for (size_t i = 0; i < pres->count_planes; ++i) {
		if (get_plane_prop(
			    cfd, pres->planes[i], "type", DRM_PLANE_TYPE_OVERLAY
		    ) != type)
			continue;
		drmModePlane *plane = drmModeGetPlane(cfd, pres->planes[i]);
		if (plane == NULL)
			continue;
		// Ignore unrelated planes.
		g_debug("DRM: Plane ID %u is of type %s belongs to CRTC ID %u.",
			plane->plane_id,
			rf_plane_type(type),
			plane->crtc_id);
		if (plane->crtc_id == crtc_id)
			plane_id = plane->plane_id;
		drmModeFreePlane(plane);
		if (plane_id != 0)
			break;
	}
	drmModeFreePlaneResources(pres);
	return plane_id;
}

static int export_fb2(int cfd, struct rf_buffer *b, uint32_t fb_id)
{
	drmModeFB2 *fb = drmModeGetFB2(cfd, fb_id);
	if (fb == NULL)
		return 0;
	g_debug("Frame: Got FB2 framebuffer ID %u.", fb->fb_id);
	for (int i = 0; i < RF_MAX_FDS; ++i) {
		if (fb->handles[i] == 0)
			break;
		drmPrimeHandleToFD(cfd, fb->handles[i], DRM_CLOEXEC, &b->fds[i]);
		if (b->fds[i] < 0)
			break;
		++b->md.length;
	}
	b->md.fb_width = fb->width;
	b->md.fb_height = fb->height;
	b->md.fourcc = fb->pixel_format;
	b->md.modifier = fb->flags & DRM_MODE_FB_MODIFIERS ?
				 fb->modifier :
				 DRM_FORMAT_MOD_INVALID;
	for (unsigned int i = 0; i < b->md.length; ++i) {
		b->md.offsets[i] = fb->offsets[i];
		b->md.pitches[i] = fb->pitches[i];
	}
	drmModeFreeFB2(fb);
	return b->md.length;
}

static int export_fb(int cfd, struct rf_buffer *b, uint32_t fb_id)
{
	drmModeFB *fb = drmModeGetFB(cfd, fb_id);
	if (fb == NULL)
		return 0;
	g_debug("Frame: Got FB framebuffer ID %u.", fb->fb_id);
	if (fb->handle == 0)
		return 0;
	drmPrimeHandleToFD(cfd, fb->handle, DRM_CLOEXEC, &b->fds[0]);
	if (b->fds[0] < 0)
		return 0;
	b->md.length = 1;
	b->md.fb_width = fb->width;
	b->md.fb_height = fb->height;
	b->md.fourcc = DRM_FORMAT_XRGB8888;
	b->md.modifier = DRM_FORMAT_MOD_INVALID;
	b->md.offsets[0] = 0;
	b->md.pitches[0] = fb->pitch;
	drmModeFreeFB(fb);
	return b->md.length;
}

static int
make_buffer(int cfd, struct rf_buffer *b, uint32_t plane_id, uint32_t type)
{
	drmModePlane *plane = drmModeGetPlane(cfd, plane_id);
	if (plane == NULL)
		return 0;
	const uint32_t fb_id = plane->fb_id;
	drmModeFreePlane(plane);
	if (fb_id == 0)
		return 0;
	g_debug("Frame: Got %s plane framebuffer ID %u.",
		rf_plane_type(type),
		fb_id);
	b->md.type = type;
	b->md.crtc_x = (int32_t)get_plane_prop(cfd, plane_id, "CRTC_X", 0);
	b->md.crtc_y = (int32_t)get_plane_prop(cfd, plane_id, "CRTC_Y", 0);
	b->md.crtc_w = (uint32_t)get_plane_prop(cfd, plane_id, "CRTC_W", 0);
	b->md.crtc_h = (uint32_t)get_plane_prop(cfd, plane_id, "CRTC_H", 0);
	// These are in 16.16 fixed point, we only need integer.
	b->md.src_x =
		(uint32_t)(get_plane_prop(cfd, plane_id, "SRC_X", 0) >> 16);
	b->md.src_y =
		(uint32_t)(get_plane_prop(cfd, plane_id, "SRC_Y", 0) >> 16);
	b->md.src_w =
		(uint32_t)(get_plane_prop(cfd, plane_id, "SRC_W", 0) >> 16);
	b->md.src_h =
		(uint32_t)(get_plane_prop(cfd, plane_id, "SRC_H", 0) >> 16);

	int ret = 0;
	// GUnixFDList refuses to send invalid fds like -1, so we need
	// to pass the number of fds. We assume valid planes are
	// continuous.
	b->md.length = 0;
	for (int i = 0; i < RF_MAX_FDS; ++i) {
		b->fds[i] = -1;
		b->md.offsets[i] = 0;
		b->md.pitches[i] = 0;
	}
	// Export DRM framebuffer to fds and metadata that EGL can import.
	ret = export_fb2(cfd, b, fb_id);
	if (ret <= 0)
		ret = export_fb(cfd, b, fb_id);
	if (ret <= 0)
		return ret;
	rf_buffer_debug(b);
	return ret;
}

static ssize_t
send_buffer(GSocketConnection *connection, struct rf_buffer *b, GError **error)
{
	ssize_t ret = 0;
	GOutputVector iov = { &b->md, sizeof(b->md) };
	GUnixFDList *fds = g_unix_fd_list_new();
	// This won't take the ownership so we need to close fds.
	//
	// See <https://docs.gtk.org/gio/method.UnixFDList.append.html>.
	for (unsigned int i = 0; i < b->md.length; ++i)
		g_unix_fd_list_append(fds, b->fds[i], NULL);
	// This won't take the ownership so we need to free GUnixFDList.
	GSocketControlMessage *msg = g_unix_fd_message_new_with_fd_list(fds);
	GSocket *socket = g_socket_connection_get_socket(connection);
	ret = g_socket_send_message(
		socket, NULL, &iov, 1, &msg, 1, G_SOCKET_MSG_NONE, NULL, error
	);
	g_clear_object(&fds);
	g_clear_object(&msg);
	return ret;
}

static ssize_t
send_frame_msg(struct this *this, size_t length, struct rf_buffer *bufs)
{
	ssize_t ret = 0;
	g_autoptr(GError) error = NULL;

	ret = rf_send_header(
		this->connection, RF_MSG_TYPE_FRAME, length, &error
	);
	if (ret <= 0)
		goto out;
	for (size_t i = 0; i < length; ++i) {
		ret = send_buffer(this->connection, &bufs[i], &error);
		if (ret <= 0)
			break;
	}

out:
	if (ret < 0)
		g_warning("Frame: Failed to send frame: %s.", error->message);
	return ret;
}

// Shared cursor-owner file helpers. The file holds the DRM connector name of the
// monitor that last received pointer input (i.e. where the cursor is). Access is
// serialized with an exclusive flock so the streamers don't race.

// Record THIS monitor as the cursor owner (called from the input path after
// relocating the cursor onto this monitor).
static void cursor_owner_publish(struct this *this)
{
	int fd = open(this->owner_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		g_warning(
			"Cursor: Failed to open %s for publish: %s.",
			this->owner_path,
			strerror(errno)
		);
		return;
	}
	if (flock(fd, LOCK_EX) == 0) {
		const char *name = this->connector_name != NULL ?
					   this->connector_name :
					   "";
		size_t len = strlen(name) + 1;
		// Overwrite AND truncate under the lock (never truncate at open() via
		// O_TRUNC, which happens before flock and would let a sibling reading
		// under LOCK_SH momentarily see an empty file -> spurious relocate).
		if (lseek(fd, 0, SEEK_SET) != 0 ||
		    write(fd, name, len) != (ssize_t)len ||
		    ftruncate(fd, len) != 0)
			g_warning("Cursor: Failed to write owner identity.");
	}
	close(fd);
}

// Read the current owner's connector name into `owner` (NUL-terminated). Returns
// true on success; false if the file is missing/empty/unreadable (unknown owner).
static bool cursor_owner_read(struct this *this, char *owner, size_t owner_size)
{
	int fd = open(this->owner_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	bool ok = false;
	if (flock(fd, LOCK_SH) == 0) {
		ssize_t n = read(fd, owner, owner_size - 1);
		if (n > 0) {
			owner[n] = '\0';
			ok = true;
		}
	}
	close(fd);
	return ok;
}

// Precompute this monitor's relocation geometry from the sibling monitor configs
// in this config's directory. Finds the layout extremes (min/max relocate-origin-x
// among relocate-enabled monitors): the min is the left wall (the anchor for a
// middle monitor), and comparing our origin to the extremes classifies us as left
// edge, right edge, or middle. An edge clamps against its own outer wall; a middle
// anchors at the left wall then fires a calibrated burst.
static void compute_relocate_geometry(struct this *this)
{
	int lo = this->relocate_origin_x;
	int hi = this->relocate_origin_x;
	g_autoptr(GDir) gdir = g_dir_open(this->config_dir, 0, NULL);
	if (gdir != NULL) {
		const char *name;
		while ((name = g_dir_read_name(gdir)) != NULL) {
			if (!g_str_has_suffix(name, ".conf"))
				continue;
			g_autofree char *path =
				g_build_filename(this->config_dir, name, NULL);
			g_autoptr(RfConfig) sib = rf_config_new(path);
			if (!rf_config_get_relocate(sib))
				continue;
			int ox = rf_config_get_relocate_origin_x(sib);
			if (ox < lo)
				lo = ox;
			if (ox > hi)
				hi = ox;
		}
	}
	this->left_wall_x = lo;
	if (lo == hi) {
		g_warning(
			"Cursor: %s found no peer monitor with a distinct "
			"relocate-origin-x; treating as an edge. Set "
			"relocate-origin-x on all participating monitors.",
			this->connector_name
		);
		this->kind = RELOCATE_LEFT_EDGE;
		return;
	}
	if (this->relocate_origin_x <= lo)
		this->kind = RELOCATE_LEFT_EDGE;
	else if (this->relocate_origin_x >= hi)
		this->kind = RELOCATE_RIGHT_EDGE;
	else
		this->kind = RELOCATE_MIDDLE;
}

static ssize_t on_frame_msg(struct this *this)
{
	g_debug("Frame: Received frame message.");

	struct rf_buffer bufs[RF_MAX_BUFS];
	ssize_t ret = 0;
	size_t length = 0;
	g_autoptr(GError) error = NULL;
	GInputStream *is =
		g_io_stream_get_input_stream(G_IO_STREAM(this->connection));

	ret = g_input_stream_read(is, &length, sizeof(length), NULL, &error);
	if (ret <= 0) {
		if (ret < 0)
			g_warning(
				"Frame: Failed to receive frame message: %s.",
				error->message
			);
		return ret;
	}

	// CRTC size.
	drmModeCrtc *crtc = drmModeGetCrtc(this->cfd, this->crtc_id);
	// Empty CRTC, maybe locked screen and turned monitor off, skip it.
	if (crtc == NULL) {
		g_debug("Frame: Got empty CRTC.");
		ret = send_frame_msg(this, 0, NULL);
		return ret;
	}
	for (size_t i = 0; i < RF_MAX_BUFS; ++i) {
		bufs[i].md.crtc_width = crtc->width;
		bufs[i].md.crtc_height = crtc->height;
	}
	drmModeFreeCrtc(crtc);

	// Primary plane.
	length = 0;
	ret = make_buffer(
		this->cfd,
		&bufs[length++],
		this->primary_id,
		DRM_PLANE_TYPE_PRIMARY
	);
	// Empty buffer, maybe locked screen and turned monitor off, skip it.
	if (ret <= 0) {
		g_debug("Frame: Got empty buffer for primary plane.");
		ret = send_frame_msg(this, 0, NULL);
		return ret;
	}

	// Cursor plane.
	if (this->cursor && this->cursor_id == 0)
		this->cursor_id = get_plane_id(
			this->cfd, this->crtc_id, DRM_PLANE_TYPE_CURSOR
		);
	if (this->cursor_id != 0) {
		ret = make_buffer(
			this->cfd,
			&bufs[length++],
			this->cursor_id,
			DRM_PLANE_TYPE_CURSOR
		);
		// It is OK to ignore cursor plane if failed.
		if (ret <= 0)
			--length;
	}

	ret = send_frame_msg(this, length, bufs);

	for (size_t i = 0; i < length; ++i)
		for (unsigned int j = 0; j < bufs[i].md.length; ++j)
			close(bufs[i].fds[j]);
	return ret;
}

// Emit `steps` small relative steps (axis = REL_X/REL_Y, sign = dir) on the
// relative-only device. COSMIC ignores a single huge relative delta but honors
// many small steps spaced a few ms apart (issue #36 means the motion must come
// from a non-absolute device).
static void relocate_burst(struct this *this, int axis, int dir, int steps)
{
	struct input_event step[2];
	memset(step, 0, sizeof(step));
	step[0].type = EV_REL;
	step[0].code = axis;
	step[0].value = dir * RELOCATE_STEP_PX;
	step[1].type = EV_SYN;
	step[1].code = SYN_REPORT;
	step[1].value = 0;
	for (int i = 0; i < steps; ++i) {
		write_may(this->ufd_rel, step, sizeof(step));
		g_usleep(RELOCATE_STEP_DELAY_US);
	}
}

// Find this monitor's own rect in the pushed layout by DRM connector name, or
// NULL if there is no layout / it is absent (then relocation uses the config
// fallback below).
static const struct rf_monitor *layout_self(struct this *this)
{
	for (unsigned int i = 0; i < this->layout_n; ++i) {
		if (g_strcmp0(this->layout[i].connector,
			      this->connector_name) == 0)
			return &this->layout[i];
	}
	return NULL;
}

// 2-D relocation from the live layout: (1) anchor at the desktop's top-left
// corner (over-travel left, then up); (2) drop into the monitors' common
// Y-overlap band; (3) sweep right to our horizontal center. Down-before-right
// keeps the path inside the monitor union at every crossing, so a monitor that is
// vertically offset from the anchor (e.g. below the leftmost's top strip) is still
// reached — this is what a horizontal-only burst could not do. The huge landing
// tolerance (half a monitor wide, ~a whole band tall) absorbs the rough gain; the
// following absolute event snaps the cursor precisely.
static void
cursor_relocate_layout(struct this *this, const struct rf_monitor *self)
{
	int min_x = self->x;
	int min_y = self->y;
	int max_right = self->x + (int)self->w;
	int max_bottom = self->y + (int)self->h;
	int anchor_y = self->y; // top of the leftmost column (the anchor corner)
	int band_top = self->y;
	int band_bottom = self->y + (int)self->h;
	for (unsigned int i = 0; i < this->layout_n; ++i) {
		const struct rf_monitor *m = &this->layout[i];
		if (m->x < min_x) {
			min_x = m->x;
			anchor_y = m->y;
		} else if (m->x == min_x && m->y < anchor_y) {
			// Topmost monitor of the leftmost column: the up-anchor
			// clamps here, so the drop is measured from this row.
			anchor_y = m->y;
		}
		if (m->y < min_y)
			min_y = m->y;
		if (m->x + (int)m->w > max_right)
			max_right = m->x + (int)m->w;
		if (m->y + (int)m->h > max_bottom)
			max_bottom = m->y + (int)m->h;
		if (m->y > band_top)
			band_top = m->y;
		if (m->y + (int)m->h < band_bottom)
			band_bottom = m->y + (int)m->h;
	}

	// Over-travel enough to clamp even on a desktop wider/taller than a fixed
	// step count would cover: the full span (through the gain) plus the margin.
	int anchor_x_steps =
		(int)((max_right - min_x) / RELOCATE_GAIN) / RELOCATE_STEP_PX +
		RELOCATE_ANCHOR_STEPS;
	int anchor_y_steps =
		(int)((max_bottom - min_y) / RELOCATE_GAIN) / RELOCATE_STEP_PX +
		RELOCATE_ANCHOR_STEPS;

	// Phase 1: anchor at (min_x, top of the leftmost column).
	relocate_burst(this, REL_X, -1, anchor_x_steps);
	relocate_burst(this, REL_Y, -1, anchor_y_steps);

	// Phase 2: drop to the common band's center (max tolerance). If the monitors
	// share no common band (exotic layout), aim for our own vertical center.
	int target_y = band_bottom > band_top ? (band_top + band_bottom) / 2 :
						self->y + (int)self->h / 2;
	int down_px = target_y - anchor_y;
	if (down_px > 0)
		relocate_burst(
			this,
			REL_Y,
			1,
			(int)(down_px / RELOCATE_GAIN) / RELOCATE_STEP_PX
		);

	// Phase 3: sweep right to our horizontal center.
	int target_x = self->x + (int)self->w / 2;
	int right_px = target_x - min_x;
	if (right_px > 0)
		relocate_burst(
			this,
			REL_X,
			1,
			(int)(right_px / RELOCATE_GAIN) / RELOCATE_STEP_PX
		);
}

// Bring the system cursor onto THIS monitor from wherever it currently is. Prefer
// the live layout (full 2-D). Fall back to the config-derived 1-D anchor+burst
// (login screen / headless, or a monitor absent from the layout): over-travel to a
// known wall; an edge monitor clamps inside itself and is done, a middle monitor
// then bursts right by a calibrated amount to land within its span. Either way the
// following absolute event snaps the cursor precisely.
static void cursor_relocate(struct this *this)
{
	const struct rf_monitor *self =
		this->layout != NULL ? layout_self(this) : NULL;
	if (self != NULL) {
		cursor_relocate_layout(this, self);
		return;
	}

	int anchor_dir = (this->kind == RELOCATE_RIGHT_EDGE) ? 1 : -1;
	relocate_burst(this, REL_X, anchor_dir, RELOCATE_ANCHOR_STEPS);
	if (this->kind != RELOCATE_MIDDLE)
		return;
	int target_x = this->relocate_origin_x + this->width / 2;
	int desktop_px = target_x - this->left_wall_x;
	if (desktop_px < 0)
		desktop_px = 0;
	int steps = (int)(desktop_px / RELOCATE_GAIN) / RELOCATE_STEP_PX;
	relocate_burst(this, REL_X, 1, steps);
}

static ssize_t on_input_msg(struct this *this)
{
	g_debug("Input: Received input message.");

	g_autofree struct input_event *ies = NULL;
	ssize_t ret = 0;
	size_t length = 0;
	g_autoptr(GError) error = NULL;
	GInputStream *is =
		g_io_stream_get_input_stream(G_IO_STREAM(this->connection));

	ret = g_input_stream_read(is, &length, sizeof(length), NULL, &error);
	if (ret <= 0)
		goto out;
	ies = g_malloc_n(length, sizeof(*ies));
	ret = g_input_stream_read(is, ies, length * sizeof(*ies), NULL, &error);
	if (ret <= 0)
		goto out;

	// "Follow the stream": this event is for THIS monitor's stream, so the user
	// wants the cursor here. If relocation is on and the cursor isn't already
	// here (owner != us, or unknown on the first input), relocate it with a
	// relative burst, then forward the absolute event for precise placement.
	// Within a monitor it stays pure absolute.
	if (this->relocate) {
		char owner[RF_CONNECTOR_MAX] = { 0 };
		bool known = cursor_owner_read(this, owner, sizeof(owner));
		if (!known || g_strcmp0(owner, this->connector_name) != 0) {
			// The anchor+burst is start-position-independent (it over-travels
			// to a known corner first), so the current owner only decides
			// WHETHER to relocate, not which direction.
			g_message(
				"Cursor: Relocating to this monitor %s.",
				this->connector_name
			);
			cursor_relocate(this);
			// Claim ownership so we don't re-burst on the next input here.
			cursor_owner_publish(this);
		}
	}

	write_may(this->ufd, ies, length * sizeof(*ies));

out:
	if (ret < 0)
		g_warning(
			"Input: Failed to receive input events: %s.",
			error->message
		);
	else if (ret > 0)
		g_debug("Input: Received %lu * %ld bytes input events.",
			length,
			sizeof(*ies));
	return ret;
}

// Adopt the live monitor layout pushed from the session (via the server). It
// supersedes the config-derived geometry and enables 2-D relocation.
static ssize_t on_layout_msg(struct this *this)
{
	size_t length = 0;
	ssize_t ret = 0;
	bool found = false;
	g_autofree struct rf_monitor *mons = NULL;
	g_autoptr(GError) error = NULL;
	GInputStream *is =
		g_io_stream_get_input_stream(G_IO_STREAM(this->connection));

	ret = g_input_stream_read(is, &length, sizeof(length), NULL, &error);
	if (ret <= 0)
		goto out;
	if (length == 0 || length > RF_MONITOR_MAX) {
		g_warning("Layout: Invalid monitor count %zu; dropping.", length);
		return -1;
	}
	mons = g_new0(struct rf_monitor, length);
	ret = g_input_stream_read(is, mons, length * sizeof(*mons), NULL, &error);
	if (ret <= 0)
		goto out;

	// Only adopt a layout that actually describes this monitor; this guards
	// against a stray/foreign session (e.g. a remote virtual desktop) pushing
	// geometry for a different set of outputs.
	for (size_t i = 0; i < length; ++i) {
		if (g_strcmp0(mons[i].connector, this->connector_name) == 0) {
			found = true;
			break;
		}
	}
	if (found) {
		g_clear_pointer(&this->layout, g_free);
		this->layout = g_steal_pointer(&mons);
		this->layout_n = (unsigned int)length;
		g_debug("Layout: Adopted %zu monitors for relocation.", length);
	} else {
		g_warning(
			"Layout: %zu monitors received but none match %s; ignoring.",
			length,
			this->connector_name != NULL ? this->connector_name : "?"
		);
	}

out:
	if (ret < 0)
		g_warning(
			"Layout: Failed to receive monitor layout: %s.",
			error->message
		);
	return ret;
}

static ssize_t send_card_path_msg(struct this *this, const char *card_path)
{
	ssize_t ret = 0;
	size_t length = strlen(card_path) + 1;
	g_autoptr(GError) error = NULL;
	GOutputStream *os =
		g_io_stream_get_output_stream(G_IO_STREAM(this->connection));

	ret = rf_send_header(
		this->connection, RF_MSG_TYPE_CARD_PATH, length, &error
	);
	if (ret <= 0)
		goto out;
	ret = g_output_stream_write(os, card_path, length, NULL, &error);

out:
	if (ret < 0)
		g_warning("DRM: Failed to send card path: %s.", error->message);
	return ret;
}

static ssize_t
send_connector_name_msg(struct this *this, const char *connector_name)
{
	ssize_t ret = 0;
	size_t length = strlen(connector_name) + 1;
	g_autoptr(GError) error = NULL;
	GOutputStream *os =
		g_io_stream_get_output_stream(G_IO_STREAM(this->connection));

	ret = rf_send_header(
		this->connection, RF_MSG_TYPE_CONNECTOR_NAME, length, &error
	);
	if (ret <= 0)
		goto out;
	ret = g_output_stream_write(os, connector_name, length, NULL, &error);
out:
	if (ret < 0)
		g_warning(
			"DRM: Failed to send connector name: %s.",
			error->message
		);
	return ret;
}

static inline char *get_connector_name(drmModeConnector *connector)
{
	return g_strdup_printf(
		"%s-%d",
		drmModeGetConnectorTypeName(connector->connector_type),
		connector->connector_type_id
	);
}

static drmModeCrtc *get_crtc(int cfd, drmModeConnector *connector)
{
	drmModeEncoder *encoder = NULL;
	drmModeCrtc *crtc = NULL;
	encoder = drmModeGetEncoder(cfd, connector->encoder_id);
	if (encoder == NULL)
		return NULL;
	crtc = drmModeGetCrtc(cfd, encoder->crtc_id);
	drmModeFreeEncoder(encoder);
	return crtc;
}

static drmModeConnector *get_connector(int cfd, const char *connector_name)
{
	drmModeConnector *connector = NULL;
	drmModeRes *res = drmModeGetResources(cfd);
	if (res == NULL) {
		g_warning("DRM: Failed to get resources.");
		return NULL;
	}
	if (connector_name != NULL)
		g_debug("DRM: Finding connector for %s.", connector_name);
	for (int i = 0; i < res->count_connectors; ++i) {
		connector = drmModeGetConnector(cfd, res->connectors[i]);
		if (connector == NULL)
			continue;
		g_autofree char *full_name = get_connector_name(connector);
		bool connected = connector->connection == DRM_MODE_CONNECTED;
		drmModeCrtc *crtc = get_crtc(cfd, connector);
		bool has_crtc = crtc != NULL;
		if (crtc != NULL)
			drmModeFreeCrtc(crtc);
		bool matched = connector_name == NULL ||
			       g_strcmp0(full_name, connector_name) == 0;
		g_debug("DRM: Connector %s is %s and %s.",
			full_name,
			connected ? "connected" : "disconnected",
			has_crtc ? "has active CRTC" : "has no active CRTC");
		if (connected && has_crtc && matched)
			break;
		drmModeFreeConnector(connector);
		connector = NULL;
	}
	drmModeFreeResources(res);
	return connector;
}

static drmModeConnector *
get_usable_card_and_connector(struct this *this, const char *connector_name)
{
	g_autoptr(GDir) dir = g_dir_open("/dev/dri", 0, NULL);
	if (dir == NULL)
		return NULL;
	const char *name = NULL;
	while ((name = g_dir_read_name(dir)) != NULL) {
		if (!g_str_has_prefix(name, "card"))
			continue;
		g_autofree char *card_path = g_build_filename(
			G_DIR_SEPARATOR_S "dev", "dri", name, NULL
		);
		int cfd = open(card_path, O_RDONLY | O_CLOEXEC);
		if (cfd < 0)
			continue;
		g_debug("DRM: Finding the first usable connector on card %s.",
			card_path);
		drmModeConnector *connector =
			get_connector(cfd, connector_name);
		if (connector != NULL) {
			this->cfd = cfd;
			this->card_path = g_strdup(card_path);
			g_message(
				"DRM: Found the first usable connector on card %s.",
				card_path
			);
			return connector;
		}
		close(cfd);
	}
	return NULL;
}

static drmModeConnector *
get_card_and_connector(struct this *this, const char *connector_name)
{
	if (this->card_path == NULL)
		return get_usable_card_and_connector(this, connector_name);
	this->cfd = open(this->card_path, O_RDONLY | O_CLOEXEC);
	if (this->cfd < 0) {
		g_warning(
			"DRM: Failed to open card %s: %s.",
			this->card_path,
			strerror(errno)
		);
		return NULL;
	}
	g_message("DRM: Opened card %s.", this->card_path);
	return get_connector(this->cfd, connector_name);
}

static void setup_drm(struct this *this)
{
	this->crtc_id = 0;
	this->primary_id = 0;
	this->cursor_id = 0;
	this->cursor = true;

	this->card_path = rf_config_get_card_path(this->config);
	this->connector_name = rf_config_get_connector(this->config);
	drmModeConnector *connector =
		get_card_and_connector(this, this->connector_name);
	if (connector == NULL)
		g_error("DRM: Failed to find a usable connector.");

	// We may become DRM master if we are the first process that opens DRM
	// card, then drop DRM master so we could start compositor after ReFrame.
	drmDropMaster(this->cfd);

	if (this->connector_name == NULL)
		this->connector_name = get_connector_name(connector);
	g_message("DRM: Found usable connector %s.", this->connector_name);

	drmModeCrtc *crtc = get_crtc(this->cfd, connector);
	drmModeFreeConnector(connector);
	if (crtc == NULL)
		g_error("DRM: Failed to find an active CRTC for connector %s.",
			this->connector_name);
	this->crtc_id = crtc->crtc_id;
	// Monitor pixel width, used as the calibrated-burst target for a middle
	// monitor (see cursor_relocate).
	this->width = crtc->width;
	drmModeFreeCrtc(crtc);

	// This is needed to get primary and cursor planes.
	if (drmSetClientCap(this->cfd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1) < 0)
		g_warning("DRM: Failed to set universal planes capability.");
	// This is needed to get `CRTC_X/Y` properties of planes.
	if (drmSetClientCap(this->cfd, DRM_CLIENT_CAP_ATOMIC, 1) < 0)
		g_warning("DRM: Failed to set atomic capability.");

	this->primary_id =
		get_plane_id(this->cfd, this->crtc_id, DRM_PLANE_TYPE_PRIMARY);
	if (this->primary_id == 0)
		g_error("DRM: Failed to find a primary plane for CRTC.");
	this->cursor = rf_config_get_cursor(this->config);
	g_message(
		"DRM: Cursor plane is %s.",
		this->cursor ? "enabled" : "disabled"
	);

	send_card_path_msg(this, this->card_path);
	send_connector_name_msg(this, this->connector_name);

	// Cursor relocation config. relocate-origin-x is this monitor's real desktop
	// position (owner identity + calibrated-burst target); compute_relocate_geometry
	// derives the anchor strategy from the layout. All read only when relocate is set.
	this->relocate = rf_config_get_relocate(this->config);
	if (this->relocate) {
		this->relocate_origin_x =
			rf_config_get_relocate_origin_x(this->config);
		compute_relocate_geometry(this);
		static const char *const kind_name[] = { "left-edge",
							 "right-edge",
							 "middle" };
		g_message(
			"Cursor: Relocation on, relocate-origin-x %d (%s, "
			"left-wall %d, width %d) on %s.",
			this->relocate_origin_x,
			kind_name[this->kind],
			this->left_wall_x,
			this->width,
			this->connector_name
		);
	}
}

static void clean_drm(struct this *this)
{
	if (this->cfd >= 0) {
		close(this->cfd);
		this->cfd = -1;
	}
	g_clear_pointer(&this->card_path, g_free);
	g_clear_pointer(&this->connector_name, g_free);
}

static void wakeup_uinput(struct this *this)
{
	struct input_event ies[WAKEUP_MAX_EVENTS];
	memset(ies, 0, WAKEUP_MAX_EVENTS * sizeof(*ies));

	ies[0].type = EV_REL;
	ies[0].code = REL_X;
	ies[0].value = 1;

	ies[1].type = EV_SYN;
	ies[1].code = SYN_REPORT;
	ies[1].value = 0;

	ies[2].type = EV_REL;
	ies[2].code = REL_Y;
	ies[2].value = 1;

	ies[3].type = EV_SYN;
	ies[3].code = SYN_REPORT;
	ies[3].value = 0;

	write_may(this->ufd, ies, WAKEUP_MAX_EVENTS * sizeof(*ies));
}

static void setup_uinput(struct this *this)
{
	this->ufd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (this->ufd < 0)
		this->ufd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK);
	if (this->ufd < 0)
		g_error("Input: Failed to open uinput: %s.", strerror(errno));

	ioctl_must(this->ufd, UI_SET_EVBIT, EV_SYN);
	ioctl_must(this->ufd, UI_SET_EVBIT, EV_KEY);
	ioctl_must(this->ufd, UI_SET_EVBIT, EV_ABS);
	ioctl_must(this->ufd, UI_SET_EVBIT, EV_REL);

	for (int i = 0; i < RF_KEYBOARD_MAX; ++i)
		ioctl_must(this->ufd, UI_SET_KEYBIT, i);

	ioctl_must(this->ufd, UI_SET_KEYBIT, BTN_LEFT);
	ioctl_must(this->ufd, UI_SET_KEYBIT, BTN_MIDDLE);
	ioctl_must(this->ufd, UI_SET_KEYBIT, BTN_RIGHT);
	// The back/forward side buttons on mouse.
	ioctl_must(this->ufd, UI_SET_KEYBIT, BTN_SIDE);
	ioctl_must(this->ufd, UI_SET_KEYBIT, BTN_EXTRA);

	ioctl_must(this->ufd, UI_SET_ABSBIT, ABS_X);
	ioctl_must(this->ufd, UI_SET_ABSBIT, ABS_Y);

	// It seems trying to be both touchscreen and mouse leads into bugs,
	// anyway, we only send absolute coordinates.
	//
	// See <https://github.com/AlynxZhou/reframe/issues/36>.
	// ioctl_must(this->ufd, UI_SET_RELBIT, REL_X);
	// ioctl_must(this->ufd, UI_SET_RELBIT, REL_Y);
	// (Relative motion for cross-monitor relocation goes on the separate
	// relative-only device ufd_rel below.)
	ioctl_must(this->ufd, UI_SET_RELBIT, REL_WHEEL);
	ioctl_must(this->ufd, UI_SET_RELBIT, REL_HWHEEL);

	struct uinput_abs_setup abs = { 0 };
	abs.absinfo.maximum = RF_POINTER_MAX;
	abs.absinfo.minimum = 0;
	abs.code = ABS_X;
	ioctl_must(this->ufd, UI_ABS_SETUP, &abs);
	abs.code = ABS_Y;
	ioctl_must(this->ufd, UI_ABS_SETUP, &abs);

	struct uinput_setup dev = { 0 };
	dev.id.bustype = BUS_USB;
	dev.id.vendor = 0xa3a7;
	dev.id.product = 0x0003;
	strcpy(dev.name, "reframe");
	ioctl_must(this->ufd, UI_DEV_SETUP, &dev);
	ioctl_must(this->ufd, UI_DEV_CREATE);

	// Second device: a pure RELATIVE pointer used ONLY for the cross-monitor
	// relocation burst, created only when relocation is enabled. A relative-only
	// device is honored by COSMIC for cross-monitor motion (verified on the box).
	// We declare BTN_LEFT so libinput classifies it as a mouse, but we NEVER emit
	// button events on it (the absolute device keeps button state), avoiding any
	// stuck-button risk.
	if (rf_config_get_relocate(this->config)) {
		this->ufd_rel = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
		if (this->ufd_rel < 0)
			this->ufd_rel = open("/dev/input/uinput",
					     O_WRONLY | O_NONBLOCK);
		if (this->ufd_rel < 0)
			g_error(
				"Input: Failed to open uinput for relative device: %s.",
				strerror(errno)
			);

		ioctl_must(this->ufd_rel, UI_SET_EVBIT, EV_SYN);
		ioctl_must(this->ufd_rel, UI_SET_EVBIT, EV_KEY);
		ioctl_must(this->ufd_rel, UI_SET_EVBIT, EV_REL);
		ioctl_must(this->ufd_rel, UI_SET_KEYBIT, BTN_LEFT);
		ioctl_must(this->ufd_rel, UI_SET_RELBIT, REL_X);
		ioctl_must(this->ufd_rel, UI_SET_RELBIT, REL_Y);

		struct uinput_setup dev_rel = { 0 };
		dev_rel.id.bustype = BUS_USB;
		dev_rel.id.vendor = 0xa3a7;
		dev_rel.id.product = 0x0004;
		strcpy(dev_rel.name, "reframe-rel");
		ioctl_must(this->ufd_rel, UI_DEV_SETUP, &dev_rel);
		ioctl_must(this->ufd_rel, UI_DEV_CREATE);
	}

	// If screen is turned off, we cannot get CRTC, so we have to wake it up.
	this->wakeup = rf_config_get_wakeup(this->config);
	if (this->wakeup) {
		g_message(
			"Input: Waiting for 1 second to let userspace detect the uinput device before wakeup."
		);
		g_usleep(G_USEC_PER_SEC);
		wakeup_uinput(this);
		g_message(
			"Input: Waiting for 1 second to let userspace process wakeup."
		);
		g_usleep(G_USEC_PER_SEC);
	}
}

static void clean_uinput(struct this *this)
{
	if (this->ufd >= 0) {
		ioctl_may(this->ufd, UI_DEV_DESTROY);
		close(this->ufd);
		this->ufd = -1;
	}
	if (this->ufd_rel >= 0) {
		ioctl_may(this->ufd_rel, UI_DEV_DESTROY);
		close(this->ufd_rel);
		this->ufd_rel = -1;
	}
}

static void on_sigint(int sig)
{
	// Non-zero hints that we didn't clean up.
	exit(2);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_autofree char *config_path = NULL;
	g_autofree char *socket_path = NULL;
	// `gboolean` is `int`, but `bool` may be `char`! Passing `bool` pointer
	// to `GOptionContext` leads into overflow!
	int keep_listen = false;
	int skip_auth = false;
	int version = false;
	g_autoptr(GError) error = NULL;

	GOptionEntry options[] = {
		{ "version",
		  'v',
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_NONE,
		  &version,
		  "Display version and exit.",
		  NULL },
		{ "socket",
		  's',
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_FILENAME,
		  &socket_path,
		  "Socket path to communiate.",
		  "SOCKET" },
		{ "config",
		  'c',
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_FILENAME,
		  &config_path,
		  "Configuration file path.",
		  "PATH" },
		{ "keep-listen",
		  'k',
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_NONE,
		  &keep_listen,
		  "Keep listening to socket after disconnection (debug purpose).",
		  NULL },
		{ "skip-auth",
		  'A',
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_NONE,
		  &skip_auth,
		  "Skip socket client authenticating by always OK (debug purpose).",
		  NULL },
		{ NULL,
		  0,
		  G_OPTION_FLAG_NONE,
		  G_OPTION_ARG_NONE,
		  NULL,
		  NULL,
		  NULL }
	};
	g_autoptr(GOptionContext)
		context = g_option_context_new(" - ReFrame Streamer");
	g_option_context_add_main_entries(context, options, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_warning("Failed to parse options: %s.", error->message);
		g_clear_pointer(&error, g_error_free);
	}

	if (version) {
		g_print(PROJECT_VERSION "\n");
		return 0;
	}

	// We ensure the default dir, user ensure the argument dir.
	if (socket_path == NULL) {
		g_mkdir("/tmp/reframe", 0755);
		rf_set_group("/tmp/reframe");
		socket_path = g_strdup("/tmp/reframe/reframe.sock");
	}

	g_message(
		"Keep listening mode is %s.",
		keep_listen ? "enabled" : "disabled"
	);
	g_message(
		"Skip authenticating mode is %s.",
		skip_auth ? "enabled" : "disabled"
	);
	g_message("Using configuration file %s.", config_path);
	g_message("Using socket %s.", socket_path);

	g_autofree struct this *this = g_malloc0(sizeof(*this));
	this->cfd = -1;
	this->ufd = -1;
	this->ufd_rel = -1;
	this->skip_auth = skip_auth;
	this->config = rf_config_new(config_path);
	// Directory of the config, for reading sibling monitor configs (relocation).
	this->config_dir =
		config_path != NULL ? g_path_get_dirname(config_path) : NULL;
	// Cursor-owner file lives alongside the socket (same writable runtime dir).
	g_autofree char *socket_dir = g_path_get_dirname(socket_path);
	this->owner_path = g_build_filename(socket_dir, "cursor-owner", NULL);

	g_autoptr(GSocketListener) listener = g_socket_listener_new();

#ifdef HAVE_LIBSYSTEMD
	if (sd_listen_fds(0) != 0) {
		// systemd socket.
		// We only handle 1 socket.
		const int sfd = SD_LISTEN_FDS_START;
		g_autoptr(GSocket) socket = g_socket_new_from_fd(sfd, &error);
		if (error != NULL)
			g_error("Failed to create socket from systemd fd: %s.",
				error->message);
		g_socket_listener_add_socket(listener, socket, NULL, &error);
	} else {
#endif
		// Non-systemd socket.
		g_autoptr(GSocketAddress)
			address = g_unix_socket_address_new(socket_path);
		g_remove(socket_path);
		g_socket_listener_add_address(
			listener,
			address,
			G_SOCKET_TYPE_STREAM,
			G_SOCKET_PROTOCOL_DEFAULT,
			NULL,
			NULL,
			&error
		);
		rf_set_group(socket_path);
		g_chmod(socket_path, 0660);
#ifdef HAVE_LIBSYSTEMD
	}
#endif
	if (error != NULL)
		g_error("Failed to listen to socket: %s.", error->message);

	signal(SIGINT, on_sigint);
	do {
		this->connection =
			g_socket_listener_accept(listener, NULL, NULL, &error);
		if (this->connection == NULL)
			g_error("Failed to accept connection: %s.",
				error->message);

		GSocket *socket =
			g_socket_connection_get_socket(this->connection);
		const pid_t pid = rf_get_socket_pid(socket);
		if (auth_pid(
			    this, pid, BINDIR G_DIR_SEPARATOR_S "reframe-server"
		    ) != 0) {
			g_warning("Got disallowed socket client PID %d.", pid);
			goto close;
		}

		g_message("ReFrame Server connected.");

		setup_uinput(this);
		setup_drm(this);

		while (true) {
			ssize_t ret = 0;
			GInputStream *is = g_io_stream_get_input_stream(
				G_IO_STREAM(this->connection)
			);
			char type;
			ret = g_input_stream_read(
				is, &type, sizeof(type), NULL, &error
			);
			if (ret <= 0) {
				if (ret < 0) {
					g_warning(
						"Failed to read message type: %s.",
						error->message
					);
					g_clear_pointer(&error, g_error_free);
				}
				break;
			}

			switch (type) {
			case RF_MSG_TYPE_FRAME:
				ret = on_frame_msg(this);
				break;
			case RF_MSG_TYPE_INPUT:
				ret = on_input_msg(this);
				break;
			case RF_MSG_TYPE_LAYOUT:
				ret = on_layout_msg(this);
				break;
			case RF_MSG_TYPE_AUTH:
				ret = on_auth_msg(this);
				break;
			default:
				break;
			}
			if (ret <= 0)
				break;
		}

		g_message("ReFrame Server disconnected.");

		clean_drm(this);
		clean_uinput(this);

	close:
		// Dropping the last reference of it will automatically close IO
		// streams and socket.
		g_clear_object(&this->connection);
	} while (keep_listen);

	g_socket_listener_close(listener);
	g_clear_object(&this->config);
	g_clear_pointer(&this->config_dir, g_free);
	g_clear_pointer(&this->owner_path, g_free);
	g_clear_pointer(&this->layout, g_free);

	return 0;
}
