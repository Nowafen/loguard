/* loguard-notify.c v3 (Session Monitor edition)
 *
 * Invoked by pam_exec at BOTH session open and session close (PAM_TYPE
 * tells us which). Its job is still to stay off the network and finish
 * in milliseconds -- all the heavy lifting (classification, GeoIP,
 * process monitoring, risk scoring, Telegram delivery) happens in the
 * daemon (loguardd / main.cpp), which reads the events this hook writes.
 *
 * Two kinds of events are written to /var/lib/loguard/sessions/events.jsonl:
 *   {"type":"session_start", "session_id":"...", ...session fields...}
 *   {"type":"session_end",   "session_id":"...", "ts":...}
 *
 * Session ID handling for NESTED sessions (e.g. `sudo` run inside an SSH
 * session shares the same TTY as its parent): PAM opens sessions in a
 * strict LIFO order, so we keep a small per-TTY stack file
 * (/var/lib/loguard/sessions/by_tty/<tty>) -- push a new session_id on
 * open, pop (and use) the top id on close. This correctly matches each
 * close event back to the right open event even when sessions nest.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#define CONFIG_FILE      "/etc/loguard/config.toml"
#define SESSIONS_DIR     "/var/lib/loguard/sessions"
#define BY_TTY_DIR       "/var/lib/loguard/sessions/by_tty"
#define SESSION_QUEUE    "/var/lib/loguard/sessions/events.jsonl"
#define MAXBUF 4096

/* System users/services that generate pure housekeeping noise -- these are
 * skipped entirely (not even logged as a Session) because there is no
 * security value in modeling "cron ran logrotate as uid 104" as a Session.
 * Everything else (including root, sudo, su) IS tracked. */
static const char *noise_services[] = {
    "cron", "CRON", "crond", "anacron", "at", "atd", "batch",
    "systemd", "systemd-user",
    NULL
};

static int is_noise_service(const char *service) {
    if (!service || !*service) return 0;
    for (int i = 0; noise_services[i]; i++)
        if (strcmp(service, noise_services[i]) == 0) return 1;
    return 0;
}

static int is_system_uid(uid_t uid) { return uid != 0 && uid < 1000; }

static void mkdirs(const char *path) {
    char tmp[512];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    }
    mkdir(tmp, 0700);
}

static const char *getenv_or(const char *name, const char *def) {
    const char *v = getenv(name);
    return (v && *v) ? v : def;
}

static int read_config_value(const char *key, char *out, size_t n) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return 0;
    char line[512];
    size_t klen = strlen(key);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, key, klen) != 0) continue;
        p += klen;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '=') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '"') p++;
        size_t i = 0;
        while (*p && *p != '"' && *p != '\n' && i < n - 1) out[i++] = *p++;
        out[i] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

static void json_escape_into(const char *in, char *out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\\' || c == '"') { out[j++] = '\\'; out[j++] = c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else out[j++] = c;
    }
    out[j] = '\0';
}

/* Turns "pts/0" into "pts_0" etc, so it is safe to use as a filename. */
static void sanitize_tty(const char *tty, char *out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; tty[i] && j + 1 < outsz; i++) {
        char c = tty[i];
        out[j++] = (c == '/' || c == ' ') ? '_' : c;
    }
    out[j] = '\0';
}

static void gen_session_id(char *out /* at least 17 bytes */) {
    unsigned char raw[8] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { if (read(fd, raw, sizeof(raw)) < 0) {} close(fd); }
    else {
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
        for (int i = 0; i < 8; i++) { seed = seed * 1103515245u + 12345u; raw[i] = (unsigned char)(seed >> 16); }
    }
    for (int i = 0; i < 8; i++) snprintf(out + i * 2, 3, "%02x", raw[i]);
}

/* ---- per-TTY session-id stack (handles nested PAM sessions, e.g. sudo) ---- */

static void tty_stack_push(const char *tty, const char *session_id) {
    char safe[128]; sanitize_tty(tty, safe, sizeof(safe));
    char path[400]; snprintf(path, sizeof(path), "%s/%s.stack", BY_TTY_DIR, safe);
    mkdirs(BY_TTY_DIR);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    if (flock(fd, LOCK_EX) == 0) {
        char line[64]; int n = snprintf(line, sizeof(line), "%s\n", session_id);
        if (write(fd, line, (size_t)n) < 0) {}
        flock(fd, LOCK_UN);
    }
    close(fd);
}

/* Pops (removes+returns) the top id. Returns 1 on success, 0 if empty/missing. */
static int tty_stack_pop(const char *tty, char *out, size_t outsz) {
    char safe[128]; sanitize_tty(tty, safe, sizeof(safe));
    char path[400]; snprintf(path, sizeof(path), "%s/%s.stack", BY_TTY_DIR, safe);

    int fd = open(path, O_RDWR);
    if (fd < 0) return 0;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return 0; }

    /* Read the whole file. */
    char buf[4096]; ssize_t total = 0; ssize_t r;
    while (total < (ssize_t)sizeof(buf) - 1 &&
           (r = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0) total += r;
    buf[total] = '\0';

    /* Find the last non-empty line. */
    char *last_start = NULL, *last_end = NULL;
    char *p = buf;
    while (*p) {
        char *line_start = p;
        char *nl = strchr(p, '\n');
        if (!nl) break;
        if (nl != line_start) { last_start = line_start; last_end = nl; }
        p = nl + 1;
    }

    int found = 0;
    if (last_start) {
        size_t len = (size_t)(last_end - last_start);
        if (len >= outsz) len = outsz - 1;
        memcpy(out, last_start, len);
        out[len] = '\0';
        found = 1;

        /* Rewrite the file without that last line. */
        size_t keep_len = (size_t)(last_start - buf);
        ftruncate(fd, 0);
        lseek(fd, 0, SEEK_SET);
        if (keep_len > 0) { if (write(fd, buf, keep_len) < 0) {} }
    }

    flock(fd, LOCK_UN);
    close(fd);
    return found;
}

/* ---- writing events ---- */

static void append_event(const char *json_line) {
    mkdirs(SESSIONS_DIR);
    int fd = open(SESSION_QUEUE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    if (flock(fd, LOCK_EX) == 0) {
        size_t len = strlen(json_line);
        if (write(fd, json_line, len) < 0) {}
        flock(fd, LOCK_UN);
    }
    close(fd);
}

static const char *detect_auth_method(void) {
    /* Best-effort only: sshd does not universally expose the auth method
     * to pam_exec. SSH_AUTH_INFO_0 is populated on some builds/configs. */
    const char *info = getenv("SSH_AUTH_INFO_0");
    if (info) {
        if (strstr(info, "publickey")) return "Public Key";
        if (strstr(info, "password")) return "Password";
        if (strstr(info, "keyboard-interactive")) return "Keyboard Interactive";
    }
    return "Unknown";
}

int main(void) {
    const char *pam_type = getenv("PAM_TYPE");
    if (!pam_type) return 0;

    const char *user = getenv_or("PAM_USER", "unknown");
    const char *service = getenv_or("PAM_SERVICE", "unknown");
    const char *tty = getenv_or("PAM_TTY", "unknown");

    if (is_noise_service(service)) return 0; /* cron/systemd housekeeping: never modeled as a Session */

    struct passwd *pw = getpwnam(user);
    uid_t uid = pw ? pw->pw_uid : (uid_t)-1;

    if (strcmp(pam_type, "close_session") == 0) {
        char session_id[64];
        if (!tty_stack_pop(tty, session_id, sizeof(session_id))) return 0; /* no matching open -- nothing to close */
        char line[256];
        int len = snprintf(line, sizeof(line), "{\"type\":\"session_end\",\"session_id\":\"%s\",\"ts\":%ld}\n",
                            session_id, (long)time(NULL));
        if (len > 0) append_event(line);
        return 0;
    }

    if (strcmp(pam_type, "open_session") != 0) return 0;

    if (access(CONFIG_FILE, F_OK) != 0) return 0; /* not configured yet */

    char session_id[17];
    gen_session_id(session_id);
    tty_stack_push(tty, session_id);

    char hostname_cfg[256] = {0};
    char sys_hostname[256] = "unknown-host";
    gethostname(sys_hostname, sizeof(sys_hostname));
    if (!read_config_value("hostname", hostname_cfg, sizeof(hostname_cfg)) || !hostname_cfg[0]) {
        strncpy(hostname_cfg, sys_hostname, sizeof(hostname_cfg) - 1);
    }

    const char *rhost = getenv("PAM_RHOST");
    const char *ssh_client = getenv("SSH_CLIENT");
    char source_ip[256] = "local";
    int remote = 0;
    if (rhost && *rhost && strcmp(rhost, "?") != 0) {
        strncpy(source_ip, rhost, sizeof(source_ip) - 1);
        remote = 1;
    } else if (ssh_client && *ssh_client) {
        char tmp[256]; strncpy(tmp, ssh_client, sizeof(tmp) - 1); tmp[sizeof(tmp)-1] = 0;
        char *sp = strchr(tmp, ' ');
        if (sp) *sp = '\0';
        strncpy(source_ip, tmp, sizeof(source_ip) - 1);
        remote = 1;
    }

    char group_name[128] = "unknown";
    if (pw) {
        struct group *gr = getgrgid(pw->pw_gid);
        if (gr) strncpy(group_name, gr->gr_name, sizeof(group_name) - 1);
    }

    const char *shell = (pw && pw->pw_shell[0]) ? pw->pw_shell : "/bin/sh";
    const char *home  = (pw && pw->pw_dir[0]) ? pw->pw_dir : "/";
    const char *auth_method = detect_auth_method();

    int interactive = (strncmp(tty, "pts/", 4) == 0 || strncmp(tty, "tty", 3) == 0) ? 1 : 0;

    char e_user[300], e_service[300], e_tty[300], e_host[300], e_ip[300];
    char e_shell[600], e_home[600], e_group[300], e_auth[128];
    json_escape_into(user, e_user, sizeof(e_user));
    json_escape_into(service, e_service, sizeof(e_service));
    json_escape_into(tty, e_tty, sizeof(e_tty));
    json_escape_into(hostname_cfg, e_host, sizeof(e_host));
    json_escape_into(source_ip, e_ip, sizeof(e_ip));
    json_escape_into(shell, e_shell, sizeof(e_shell));
    json_escape_into(home, e_home, sizeof(e_home));
    json_escape_into(group_name, e_group, sizeof(e_group));
    json_escape_into(auth_method, e_auth, sizeof(e_auth));

    char line[MAXBUF];
    int len = snprintf(line, sizeof(line),
        "{\"type\":\"session_start\",\"session_id\":\"%s\",\"ts\":%ld,"
        "\"user\":\"%s\",\"uid\":%ld,\"gid\":%ld,\"group\":\"%s\","
        "\"service\":\"%s\",\"tty\":\"%s\",\"hostname\":\"%s\","
        "\"source_ip\":\"%s\",\"remote\":%s,\"auth_method\":\"%s\","
        "\"shell\":\"%s\",\"home\":\"%s\",\"interactive\":%s}\n",
        session_id, (long)time(NULL),
        e_user, (long)uid, pw ? (long)pw->pw_gid : -1L, e_group,
        e_service, e_tty, e_host,
        e_ip, remote ? "true" : "false", e_auth,
        e_shell, e_home, interactive ? "true" : "false");
    if (len < 0 || len >= (int)sizeof(line)) return 0;

    append_event(line);
    (void)is_system_uid; /* reserved for future fine-grained filtering */
    return 0;
}
