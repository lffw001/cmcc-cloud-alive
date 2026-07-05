#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <execinfo.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int in_hook = 0;

static long tid(void) {
  return (long)syscall(SYS_gettid);
}

static const char *log_path(void) {
  const char *path = getenv("ZIME_PROBE_LOG");
  return (path && path[0]) ? path : NULL;
}

static size_t max_dump_bytes(void) {
  const char *value = getenv("ZIME_PROBE_MAX_BYTES");
  if (!value || !value[0]) return 4096;
  long parsed = strtol(value, NULL, 10);
  if (parsed <= 0) return 4096;
  if (parsed > 1048576) return 1048576;
  return (size_t)parsed;
}

static size_t max_struct_dump_bytes(void) {
  const char *value = getenv("ZIME_PROBE_STRUCT_BYTES");
  if (!value || !value[0]) return 256;
  long parsed = strtol(value, NULL, 10);
  if (parsed <= 0) return 256;
  if (parsed > 4096) return 4096;
  return (size_t)parsed;
}

static int env_flag(const char *name, int default_value) {
  const char *value = getenv(name);
  if (!value || !value[0]) return default_value;
  if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
      strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
    return 1;
  }
  if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
      strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
    return 0;
  }
  return default_value;
}

static int wrap_callbacks_enabled(void) {
  return env_flag("ZIME_PROBE_WRAP_CALLBACKS", 0);
}

static int transport_capture_enabled(void) {
  return env_flag("ZIME_PROBE_CAPTURE_TRANSPORT", 0);
}

static int auth_focus_enabled(void) {
  return env_flag("ZIME_PROBE_AUTH_FOCUS", 0);
}

#ifndef ZIME_PROBE_ENABLE_CPP_INTERPOSE
#define ZIME_PROBE_ENABLE_CPP_INTERPOSE 0
#endif

#ifndef ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
#define ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE 0
#endif

static void hex_encode(const unsigned char *buf, size_t len, char *out) {
  static const char map[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = map[buf[i] >> 4];
    out[i * 2 + 1] = map[buf[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

static const char *payload_kind(const void *buf, size_t len) {
  const unsigned char *p = (const unsigned char *)buf;
  if (!p || !len) return "empty";
  if (len >= 4 && memcmp(p, "REDQ", 4) == 0) return "spice-link";
  if (len >= 21) {
    uint32_t conv = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    uint8_t cmd = p[4];
    uint16_t wnd = (uint16_t)p[5] | ((uint16_t)p[6] << 8);
    uint16_t declared_len = (uint16_t)p[19] | ((uint16_t)p[20] << 8);
    if ((wnd & 0xffc0) == 0 && declared_len <= len - 21) {
      if (cmd == 7) return "kcp-auth-head-ack";
      if (cmd == 9) return "kcp-auth-ack";
      if (conv == 0x80000006u) return "kcp-auth-head";
      if (conv == 0x80000008u) return "kcp-auth-data";
    }
  }
  if (len >= 5 && p[1] == 0x03 && p[2] <= 0x04) {
    switch (p[0]) {
      case 0x14: return "tls-change-cipher-spec";
      case 0x15: return "tls-alert";
      case 0x16: return "tls-handshake";
      case 0x17: return "tls-application-data";
      default: break;
    }
  }
  if (len >= 24 && p[0] == 1 && p[1] >= 1 && p[1] <= 3) return "chuanyun-frame";
  if (len >= 6) {
    uint16_t type = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    uint32_t size = (uint32_t)p[2] | ((uint32_t)p[3] << 8) | ((uint32_t)p[4] << 16) | ((uint32_t)p[5] << 24);
    if (size <= len - 6 || size < 65536) {
      switch (type) {
        case 0x0003: return "spice-set-ack";
        case 0x0004: return "spice-ping";
        case 0x0005: return "spice-pong";
        case 0x0006: return "spice-ack-sync";
        case 0x0007: return "spice-ack";
        case 0x0065: return "spice-display-init";
        case 0x0066: return "spice-mark";
        case 0x0067: return "spice-main-init";
        case 0x0068: return "spice-channels-list";
        case 0x0130: return "spice-draw-copy";
        case 0x013a: return "spice-surface-create";
        default: return "spice-mini-or-data";
      }
    }
  }
  if (len >= 18) {
    uint16_t type = (uint16_t)p[8] | ((uint16_t)p[9] << 8);
    uint32_t size = (uint32_t)p[10] | ((uint32_t)p[11] << 8) | ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 24);
    if (size <= len - 18 || size < 65536) {
      switch (type) {
        case 0x0003: return "spice-set-ack";
        case 0x0004: return "spice-ping";
        case 0x0005: return "spice-pong";
        case 0x0006: return "spice-ack-sync";
        case 0x0007: return "spice-ack";
        case 0x0065: return "spice-display-init";
        case 0x0066: return "spice-mark";
        case 0x0067: return "spice-main-init";
        case 0x0068: return "spice-channels-list";
        case 0x0130: return "spice-draw-copy";
        case 0x013a: return "spice-surface-create";
        default: return "spice-data";
      }
    }
  }
  return "unknown";
}

static void stack_symbols_text(char *out, size_t out_len) {
  if (!out_len) return;
  out[0] = '\0';
  if (!auth_focus_enabled()) return;
  void *frames[32];
  int n = backtrace(frames, 32);
  size_t used = 0;
  for (int i = 2; i < n; i++) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    const char *symbol = "-";
    unsigned long offset = 0;
    if (dladdr(frames[i], &info)) {
      if (info.dli_sname) symbol = info.dli_sname;
      if (info.dli_saddr) {
        offset = (unsigned long)((uintptr_t)frames[i] - (uintptr_t)info.dli_saddr);
      }
    }
    int written = snprintf(out + used, out_len - used, "%s%s+0x%lx",
                           used ? ";" : "", symbol, offset);
    if (written < 0) break;
    if ((size_t)written >= out_len - used) {
      out[out_len - 1] = '\0';
      break;
    }
    used += (size_t)written;
  }
}

static void proc_name(char *buf, size_t len) {
  if (!len) return;
  strncpy(buf, "-", len);
  buf[len - 1] = '\0';
  FILE *f = fopen("/proc/self/comm", "r");
  if (!f) return;
  if (fgets(buf, (int)len, f)) {
    buf[strcspn(buf, "\r\n")] = '\0';
  }
  fclose(f);
}

static int contains_token(const char *haystack, const char *needle) {
  return haystack && needle && needle[0] && strstr(haystack, needle) != NULL;
}

static int process_allowed(const char *name) {
  const char *all = getenv("ZIME_PROBE_LOG_ALL");
  if (all && strcmp(all, "1") == 0) return 1;

  const char *filter = getenv("ZIME_PROBE_PROCESS_FILTER");
  if (filter && filter[0]) {
    char *copy = strdup(filter);
    if (!copy) return 0;
    int ok = 0;
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
      while (*tok == ' ') tok++;
      if (contains_token(name, tok)) {
        ok = 1;
        break;
      }
    }
    free(copy);
    return ok;
  }

  return contains_token(name, "uSmartView");
}

static void log_line(const char *fmt, ...) {
  const char *path = log_path();
  if (!path || in_hook) return;
  in_hook = 1;

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  char name[256];
  proc_name(name, sizeof(name));
  if (!process_allowed(name)) {
    in_hook = 0;
    return;
  }

  char *body = NULL;
  va_list ap;
  va_start(ap, fmt);
  if (vasprintf(&body, fmt, ap) < 0) body = NULL;
  va_end(ap);
  if (!body) {
    in_hook = 0;
    return;
  }

  char *line = NULL;
  if (asprintf(&line,
               "{\"sec\":%ld,\"nsec\":%ld,\"pid\":%ld,\"tid\":%ld,\"process\":\"%s\",%s}\n",
               (long)ts.tv_sec, (long)ts.tv_nsec, (long)getpid(), tid(), name, body) < 0) {
    line = NULL;
  }
  free(body);
  if (!line) {
    in_hook = 0;
    return;
  }

  int fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
  if (fd >= 0) {
    pthread_mutex_lock(&log_mutex);
    flock(fd, LOCK_EX);
    size_t len = strlen(line);
    ssize_t unused = write(fd, line, len);
    (void)unused;
    flock(fd, LOCK_UN);
    pthread_mutex_unlock(&log_mutex);
    close(fd);
  }
  free(line);
  in_hook = 0;
}

static int should_log_current_process(void) {
  if (!log_path() || in_hook) return 0;
  static __thread pid_t cached_pid = 0;
  static __thread int cached_allowed = -1;
  pid_t pid = getpid();
  if (cached_allowed >= 0 && cached_pid == pid) return cached_allowed;
  char name[256];
  proc_name(name, sizeof(name));
  cached_pid = pid;
  cached_allowed = process_allowed(name);
  return cached_allowed;
}

static void log_buffer_event(const char *fn, const char *direction, void *engine, long channel_id, long stream_id, const void *buf, unsigned int len, int ret) {
  if (!should_log_current_process()) return;
  size_t dump_len = len;
  size_t max_len = max_dump_bytes();
  if (dump_len > max_len) dump_len = max_len;
  char *hex = NULL;
  if (buf && dump_len) {
    hex = (char *)malloc(dump_len * 2 + 1);
    if (hex) hex_encode((const unsigned char *)buf, dump_len, hex);
  }
  log_line(
      "\"event\":\"zime_buffer\",\"function\":\"%s\",\"direction\":\"%s\","
      "\"engine\":\"%p\",\"channelId\":%ld,\"streamId\":%ld,\"len\":%u,"
      "\"dumped\":%zu,\"payloadKind\":\"%s\",\"ret\":%d,\"hex\":\"%s\"",
      fn, direction, engine, channel_id, stream_id, len, dump_len,
      payload_kind(buf, len), ret, hex ? hex : "");
  free(hex);
}

static void log_callback_buffer_event(const char *fn, const char *direction, int slot, long channel_id, long stream_id, const void *buf, unsigned int len, int ret) {
  if (!should_log_current_process()) return;
  size_t dump_len = len;
  size_t max_len = max_dump_bytes();
  if (dump_len > max_len) dump_len = max_len;
  char *hex = NULL;
  if (buf && dump_len) {
    hex = (char *)malloc(dump_len * 2 + 1);
    if (hex) hex_encode((const unsigned char *)buf, dump_len, hex);
  }
  log_line(
      "\"event\":\"zime_callback_buffer\",\"function\":\"%s\",\"direction\":\"%s\","
      "\"slot\":%d,\"channelId\":%ld,\"streamId\":%ld,\"len\":%u,"
      "\"dumped\":%zu,\"payloadKind\":\"%s\",\"ret\":%d,\"hex\":\"%s\"",
      fn, direction, slot, channel_id, stream_id, len, dump_len,
      payload_kind(buf, len), ret, hex ? hex : "");
  free(hex);
}

static void log_memory_snapshot(const char *fn, const char *label, const void *ptr, size_t requested) {
  if (!should_log_current_process()) return;
  if (!ptr || !requested) return;
  size_t dump_len = requested;
  size_t max_len = max_struct_dump_bytes();
  if (dump_len > max_len) dump_len = max_len;
  char *hex = (char *)malloc(dump_len * 2 + 1);
  if (!hex) return;
  hex_encode((const unsigned char *)ptr, dump_len, hex);
  log_line(
      "\"event\":\"zime_memory\",\"function\":\"%s\",\"label\":\"%s\","
      "\"ptr\":\"%p\",\"requested\":%zu,\"dumped\":%zu,\"hex\":\"%s\"",
      fn, label, ptr, requested, dump_len, hex);
  free(hex);
}

#define ZIME_PACKET_OUT_SPEC_SIZE 0x68
#define ZIME_PACKET_OUT_SPEC_MAX_SAMPLES 16
#define ZIME_PACKET_OUT_SPEC_MAX_IOV 64
#define ZIME_PACKET_OUT_SPEC_MAX_HEX 256

static void log_ptr_table(const char *fn, void *engine, const void *table, int ret) {
  if (!should_log_current_process()) return;
  const uintptr_t *p = (const uintptr_t *)table;
  uintptr_t values[8] = {0};
  if (p) {
    for (int i = 0; i < 8; i++) values[i] = p[i];
  }
  log_line(
      "\"event\":\"zime_ptr_table\",\"function\":\"%s\",\"engine\":\"%p\","
      "\"table\":\"%p\",\"ret\":%d,\"ptr0\":\"0x%lx\",\"ptr1\":\"0x%lx\","
      "\"ptr2\":\"0x%lx\",\"ptr3\":\"0x%lx\",\"ptr4\":\"0x%lx\","
      "\"ptr5\":\"0x%lx\",\"ptr6\":\"0x%lx\",\"ptr7\":\"0x%lx\"",
      fn, engine, table, ret, (unsigned long)values[0], (unsigned long)values[1],
      (unsigned long)values[2], (unsigned long)values[3], (unsigned long)values[4],
      (unsigned long)values[5], (unsigned long)values[6], (unsigned long)values[7]);
}

static void log_ptr_symbols(const char *fn, const void *table) {
  if (!should_log_current_process()) return;
  const uintptr_t *p = (const uintptr_t *)table;
  if (!p) return;
  for (int i = 0; i < 8; i++) {
    if (!p[i]) continue;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    const char *object = "-";
    const char *symbol = "-";
    unsigned long offset = 0;
    if (dladdr((const void *)p[i], &info)) {
      if (info.dli_fname) object = info.dli_fname;
      if (info.dli_sname) symbol = info.dli_sname;
      if (info.dli_saddr) {
        offset = (unsigned long)(p[i] - (uintptr_t)info.dli_saddr);
      }
    }
    log_line(
        "\"event\":\"zime_ptr_symbol\",\"function\":\"%s\","
        "\"slot\":%d,\"ptr\":\"0x%lx\",\"object\":\"%s\","
        "\"symbol\":\"%s\",\"symbolOffset\":%lu",
        fn, i, (unsigned long)p[i], object, symbol, offset);
  }
}

#if ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
static int fd_is_socket(int fd) {
  int type = 0;
  socklen_t len = sizeof(type);
  return fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
}
#endif

static void sockaddr_text(const struct sockaddr *addr, socklen_t addrlen, char *out, size_t out_len) {
  if (!out_len) return;
  snprintf(out, out_len, "-");
  if (!addr || addrlen <= 0) return;
  if (addr->sa_family == AF_INET && addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
    snprintf(out, out_len, "%s:%u", ip, (unsigned)ntohs(in->sin_port));
  } else if (addr->sa_family == AF_INET6 && addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    char ip[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
    snprintf(out, out_len, "[%s]:%u", ip, (unsigned)ntohs(in6->sin6_port));
  } else {
    snprintf(out, out_len, "family:%d", addr->sa_family);
  }
}

#if ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
static void fd_peer_text(int fd, char *out, size_t out_len) {
  struct sockaddr_storage ss;
  socklen_t len = sizeof(ss);
  if (getpeername(fd, (struct sockaddr *)&ss, &len) == 0) {
    sockaddr_text((const struct sockaddr *)&ss, len, out, out_len);
    return;
  }
  snprintf(out, out_len, "-");
}

static void fd_local_text(int fd, char *out, size_t out_len) {
  struct sockaddr_storage ss;
  socklen_t len = sizeof(ss);
  if (getsockname(fd, (struct sockaddr *)&ss, &len) == 0) {
    sockaddr_text((const struct sockaddr *)&ss, len, out, out_len);
    return;
  }
  snprintf(out, out_len, "-");
}
#endif

static uint8_t read_u8_at(const void *ptr, size_t off) {
  const unsigned char *p = (const unsigned char *)ptr;
  return p ? p[off] : 0;
}

static uint16_t read_u16_at(const void *ptr, size_t off) {
  uint16_t value = 0;
  if (ptr) memcpy(&value, (const unsigned char *)ptr + off, sizeof(value));
  return value;
}

static uint32_t read_u32_at(const void *ptr, size_t off) {
  uint32_t value = 0;
  if (ptr) memcpy(&value, (const unsigned char *)ptr + off, sizeof(value));
  return value;
}

static uint64_t read_u64_at(const void *ptr, size_t off) {
  uint64_t value = 0;
  if (ptr) memcpy(&value, (const unsigned char *)ptr + off, sizeof(value));
  return value;
}

static void read_sockaddr_ptr_text(const void *ptr, size_t off, char *out, size_t out_len) {
  if (!out_len) return;
  snprintf(out, out_len, "-");
  if (!ptr) return;
  const struct sockaddr *addr = NULL;
  memcpy(&addr, (const unsigned char *)ptr + off, sizeof(addr));
  if (!addr) return;
  sockaddr_text(addr, (socklen_t)sizeof(struct sockaddr_storage), out, out_len);
}

static void log_zime_init_param(const char *fn, const char *label, const void *param) {
  if (!param) return;
  log_line(
      "\"event\":\"zime_struct\",\"function\":\"%s\",\"label\":\"%s\","
      "\"struct\":\"T_ZIMEInitParam_C\",\"ptr\":\"%p\","
      "\"eZIMEDCRole\":%u,\"eZIMESupportDCProtocol\":%u,"
      "\"bUDPPayloadReserve4Bytes\":%u",
      fn, label, param,
      (unsigned)read_u32_at(param, 0),
      (unsigned)read_u32_at(param, 56),
      (unsigned)read_u8_at(param, 60));
}

static void log_zime_socket_param_fields(const char *fn, const char *label, const void *param, size_t base_off) {
  if (!param) return;
  const void *socket_param = (const unsigned char *)param + base_off;
  char local[128];
  char remote[128];
  char opaque_hex[64 * 2 + 1];
  read_sockaddr_ptr_text(socket_param, 0, local, sizeof(local));
  read_sockaddr_ptr_text(socket_param, 8, remote, sizeof(remote));
  hex_encode((const unsigned char *)socket_param + 16, 64, opaque_hex);
  log_line(
      "\"event\":\"zime_struct\",\"function\":\"%s\",\"label\":\"%s\","
      "\"struct\":\"T_ZIMESocketParam_C\",\"ptr\":\"%p\","
      "\"baseOffset\":%zu,\"pLocalAddr\":\"0x%lx\",\"pRemoteAddr\":\"0x%lx\","
      "\"localAddr\":\"%s\",\"remoteAddr\":\"%s\","
      "\"nOpaqueLen\":%u,\"opaqueHexPrefix\":\"%s\"",
      fn, label, socket_param, base_off,
      (unsigned long)read_u64_at(socket_param, 0),
      (unsigned long)read_u64_at(socket_param, 8),
      local, remote,
      (unsigned)read_u32_at(socket_param, 80),
      opaque_hex);
}

static void log_zime_channel_context(const char *fn, const char *label, const void *context) {
  if (!context) return;
  log_line(
      "\"event\":\"zime_struct\",\"function\":\"%s\",\"label\":\"%s\","
      "\"struct\":\"T_ZIMEChannelContext_C\",\"ptr\":\"%p\","
      "\"eDCProtocol\":%u,\"u16BaseMTU\":%u,\"bSavePcap\":%u,"
      "\"bOpenStat\":%u,\"eBusinessType\":%u",
      fn, label, context,
      (unsigned)read_u32_at(context, 0),
      (unsigned)read_u16_at(context, 96),
      (unsigned)read_u8_at(context, 98),
      (unsigned)read_u8_at(context, 99),
      (unsigned)read_u32_at(context, 100));
  log_zime_socket_param_fields(fn, "context_socket", context, 8);
}

static void log_zime_stream_param(const char *fn, const char *label, const void *param) {
  if (!param) return;
  char payload_type_hex[32 * 2 + 1];
  hex_encode((const unsigned char *)param + 40, 32, payload_type_hex);
  log_line(
      "\"event\":\"zime_struct\",\"function\":\"%s\",\"label\":\"%s\","
      "\"struct\":\"T_ZIMEStreamParam_C\",\"ptr\":\"%p\","
      "\"mode\":%u,\"supportDropData\":%u,\"latencyThreshMs\":%u,"
      "\"u8Priority\":%u,\"u32MaxBandwidth\":%u,"
      "\"u32StreamUnsendBytes\":%u,\"bHasUnackData\":%u,"
      "\"s32BitrateKbps\":%d,\"s32NetLost\":%d,"
      "\"s32NetNetRttAvg\":%d,\"payloadTypeHex\":\"%s\"",
      fn, label, param,
      (unsigned)read_u32_at(param, 0),
      (unsigned)read_u8_at(param, 4),
      (unsigned)read_u32_at(param, 8),
      (unsigned)read_u8_at(param, 12),
      (unsigned)read_u32_at(param, 16),
      (unsigned)read_u32_at(param, 20),
      (unsigned)read_u8_at(param, 24),
      (int32_t)read_u32_at(param, 28),
      (int32_t)read_u32_at(param, 32),
      (int32_t)read_u32_at(param, 36),
      payload_type_hex);
}

static void log_zime_socket_param(const char *fn, const char *label, const void *param) {
  log_zime_socket_param_fields(fn, label, param, 0);
}

static void log_zime_packet_specs(const char *fn, const void *packet_specs, size_t count) {
  if (!should_log_current_process()) return;
  if (!packet_specs || !count) return;
  size_t sample_count = count;
  if (sample_count > ZIME_PACKET_OUT_SPEC_MAX_SAMPLES) sample_count = ZIME_PACKET_OUT_SPEC_MAX_SAMPLES;
  for (size_t i = 0; i < sample_count; i++) {
    const unsigned char *spec = (const unsigned char *)packet_specs + (i * ZIME_PACKET_OUT_SPEC_SIZE);
    uintptr_t iov_ptr = (uintptr_t)read_u64_at(spec, 0);
    uint64_t iov_count = read_u64_at(spec, 8);
    uintptr_t local_ptr = (uintptr_t)read_u64_at(spec, 16);
    uintptr_t dest_ptr = (uintptr_t)read_u64_at(spec, 24);
    unsigned int embedded_family = read_u16_at(spec, 32);
    unsigned int addr_len = read_u8_at(spec, 96);
    char local[128];
    char dest[128];
    char embedded[128];
    sockaddr_text((const struct sockaddr *)local_ptr, (socklen_t)sizeof(struct sockaddr_storage), local, sizeof(local));
    sockaddr_text((const struct sockaddr *)dest_ptr, (socklen_t)sizeof(struct sockaddr_storage), dest, sizeof(dest));
    sockaddr_text((const struct sockaddr *)(spec + 32), (socklen_t)(addr_len ? addr_len : sizeof(struct sockaddr_storage)), embedded, sizeof(embedded));

    unsigned long long total_iov_bytes = 0;
    unsigned long long first_iov_len = 0;
    const void *first_iov_base = NULL;
    const char *first_kind = "empty";
    char *first_hex = NULL;
    if (iov_ptr && iov_count > 0 && iov_count <= ZIME_PACKET_OUT_SPEC_MAX_IOV) {
      const struct iovec *iov = (const struct iovec *)iov_ptr;
      for (uint64_t j = 0; j < iov_count; j++) {
        total_iov_bytes += (unsigned long long)iov[j].iov_len;
      }
      first_iov_base = iov[0].iov_base;
      first_iov_len = (unsigned long long)iov[0].iov_len;
      if (first_iov_base && first_iov_len > 0) {
        size_t dump_len = (size_t)first_iov_len;
        if (dump_len > max_dump_bytes()) dump_len = max_dump_bytes();
        if (dump_len > ZIME_PACKET_OUT_SPEC_MAX_HEX) dump_len = ZIME_PACKET_OUT_SPEC_MAX_HEX;
        first_hex = (char *)malloc(dump_len * 2 + 1);
        if (first_hex) hex_encode((const unsigned char *)first_iov_base, dump_len, first_hex);
        first_kind = payload_kind(first_iov_base, (size_t)first_iov_len);
      }
    }

    log_line(
        "\"event\":\"zime_packet_spec\",\"function\":\"%s\","
        "\"index\":%zu,\"count\":%zu,\"specPtr\":\"%p\","
        "\"specSize\":%u,\"layout\":\"ZIMEPacketOutSpec_candidate_v1\","
        "\"iov\":\"0x%lx\",\"iovCount\":%llu,\"totalIovBytes\":%llu,"
        "\"firstIovBase\":\"%p\",\"firstIovLen\":%llu,"
        "\"firstIovPayloadKind\":\"%s\",\"firstIovHexPrefix\":\"%s\","
        "\"localAddrPtr\":\"0x%lx\",\"destAddrPtr\":\"0x%lx\","
        "\"localAddr\":\"%s\",\"destAddr\":\"%s\","
        "\"embeddedAddrFamily\":%u,\"embeddedAddr\":\"%s\",\"addrLen\":%u,"
        "\"traceOnly\":true",
        fn, i, count, spec, (unsigned)ZIME_PACKET_OUT_SPEC_SIZE,
        (unsigned long)iov_ptr, (unsigned long long)iov_count,
        total_iov_bytes, first_iov_base, first_iov_len, first_kind, first_hex ? first_hex : "",
        (unsigned long)local_ptr, (unsigned long)dest_ptr, local, dest,
        embedded_family, embedded, addr_len);
    free(first_hex);
  }
}

#if ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
static void log_transport_buffer_ex(const char *fn, const char *direction, int fd, const void *buf, size_t len, ssize_t ret, const struct sockaddr *addr, socklen_t addrlen) {
  if (!transport_capture_enabled()) return;
  if (!should_log_current_process()) return;
  if (ret <= 0 || !buf || !len || !fd_is_socket(fd)) return;
  size_t actual = (size_t)ret;
  if (actual > len) actual = len;
  size_t dump_len = actual;
  size_t max_len = max_dump_bytes();
  if (dump_len > max_len) dump_len = max_len;
  char *hex = NULL;
  if (dump_len) {
    hex = (char *)malloc(dump_len * 2 + 1);
    if (hex) hex_encode((const unsigned char *)buf, dump_len, hex);
  }
  char peer[128];
  char local[128];
  char remote[128];
  char stack[2048];
  fd_peer_text(fd, peer, sizeof(peer));
  fd_local_text(fd, local, sizeof(local));
  sockaddr_text(addr, addrlen, remote, sizeof(remote));
  stack_symbols_text(stack, sizeof(stack));
  const char *kind = payload_kind(buf, actual);
  log_line(
      "\"event\":\"transport_buffer\",\"function\":\"%s\",\"direction\":\"%s\","
      "\"fd\":%d,\"peer\":\"%s\",\"local\":\"%s\",\"remote\":\"%s\",\"len\":%zu,\"ret\":%zd,\"dumped\":%zu,"
      "\"payloadKind\":\"%s\",\"authFocus\":%s,\"stack\":\"%s\",\"hex\":\"%s\"",
      fn, direction, fd, peer, local, remote, len, ret, dump_len, kind,
      (auth_focus_enabled() && strstr(kind, "kcp-auth")) ? "true" : "false",
      stack, hex ? hex : "");
  free(hex);
}

static void log_transport_buffer(const char *fn, const char *direction, int fd, const void *buf, size_t len, ssize_t ret) {
  log_transport_buffer_ex(fn, direction, fd, buf, len, ret, NULL, 0);
}

static void *copy_iov_bytes(const struct iovec *iov, size_t iovlen, size_t want, size_t *copied) {
  *copied = 0;
  if (!iov || !iovlen || !want) return NULL;
  size_t max_len = max_dump_bytes();
  if (want > max_len) want = max_len;
  unsigned char *out = (unsigned char *)malloc(want);
  if (!out) return NULL;
  for (size_t i = 0; i < iovlen && *copied < want; i++) {
    size_t take = iov[i].iov_len;
    if (take > want - *copied) take = want - *copied;
    if (take && iov[i].iov_base) {
      memcpy(out + *copied, iov[i].iov_base, take);
      *copied += take;
    }
  }
  return out;
}

static void log_msg_buffer(const char *fn, const char *direction, int fd, const struct msghdr *msg, ssize_t ret) {
  if (ret <= 0 || !msg || !fd_is_socket(fd)) return;
  size_t copied = 0;
  void *buf = copy_iov_bytes(msg->msg_iov, msg->msg_iovlen, (size_t)ret, &copied);
  if (buf && copied) {
    log_transport_buffer_ex(fn, direction, fd, buf, copied, (ssize_t)copied, (const struct sockaddr *)msg->msg_name, msg->msg_namelen);
  }
  free(buf);
}

static void log_ssl_buffer(const char *fn, const char *direction, void *ssl, const void *buf, int len, int ret) {
  if (!transport_capture_enabled()) return;
  if (!should_log_current_process()) return;
  if (ret <= 0 || !buf || len <= 0) return;
  size_t actual = (size_t)ret;
  if (actual > (size_t)len) actual = (size_t)len;
  size_t dump_len = actual;
  size_t max_len = max_dump_bytes();
  if (dump_len > max_len) dump_len = max_len;
  char *hex = NULL;
  if (dump_len) {
    hex = (char *)malloc(dump_len * 2 + 1);
    if (hex) hex_encode((const unsigned char *)buf, dump_len, hex);
  }
  log_line(
      "\"event\":\"ssl_buffer\",\"function\":\"%s\",\"direction\":\"%s\","
      "\"ssl\":\"%p\",\"len\":%d,\"ret\":%d,\"dumped\":%zu,"
      "\"payloadKind\":\"%s\",\"hex\":\"%s\"",
      fn, direction, ssl, len, ret, dump_len, payload_kind(buf, actual), hex ? hex : "");
  free(hex);
}
#endif

__attribute__((constructor)) static void loaded(void) {
  log_line(
      "\"event\":\"zime_probe_loaded\","
      "\"captureTransport\":%d,\"wrapCallbacks\":%d,"
      "\"transportInterposeCompiled\":%d,\"cppInterposeCompiled\":%d",
      transport_capture_enabled(), wrap_callbacks_enabled(),
      (int)ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE,
      (int)ZIME_PROBE_ENABLE_CPP_INTERPOSE);
}

typedef void *(*create_engine_fn)(void);
typedef int (*init_fn)(void *, void *);
typedef int (*set_ptr_fn)(void *, void *);
typedef int (*create_channel_fn)(void *, void *, long *);
typedef int (*create_stream_fn)(void *, long, long *, void *);
typedef int (*zime_send_fn)(void *, long, long, const void *, unsigned int);
typedef int (*zime_send2_fn)(void *, long, long, const void *, unsigned int, void *);
typedef int (*zime_recv_fn)(void *, void *, const void *, unsigned int);
typedef int (*process2_fn)(void *, long, unsigned int *);
typedef int (*destroy_channel_fn)(void *, long);
typedef int (*destroy_stream_fn)(void *, long, long);
#if ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
typedef ssize_t (*send_real_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_real_fn)(int, void *, size_t, int);
typedef ssize_t (*sendto_real_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_real_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*sendmsg_real_fn)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_real_fn)(int, struct msghdr *, int);
typedef int (*sendmmsg_real_fn)(int, struct mmsghdr *, unsigned int, int);
typedef int (*recvmmsg_real_fn)(int, struct mmsghdr *, unsigned int, int, struct timespec *);
typedef ssize_t (*read_real_fn)(int, void *, size_t);
typedef ssize_t (*write_real_fn)(int, const void *, size_t);
typedef int (*socket_real_fn)(int, int, int);
typedef int (*bind_real_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*connect_real_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*ssl_write_real_fn)(void *, const void *, int);
typedef int (*ssl_read_real_fn)(void *, void *, int);
#endif

#define REAL_FN(name, type) ((type)dlsym(RTLD_NEXT, name))
#define REAL_FN_ONCE(name, type) ({ \
  static type real_fn = NULL; \
  if (!real_fn) real_fn = (type)dlsym(RTLD_NEXT, name); \
  real_fn; \
})

typedef int (*zime_transport_send_cb_fn)(void *, long, const void *, unsigned int);
typedef int (*zime_transport_batch_cb_fn)(const void *, size_t);
typedef int (*zime_channel_data_received_cb_fn)(long, long, const void *, unsigned int);
typedef void (*zime_channel_created_cb_fn)(long, unsigned long, int, int, int);
typedef void (*zime_channel_destroyed_cb_fn)(long, int, int);
typedef void (*zime_channel_stream_blocked_cb_fn)(long, long, unsigned char, unsigned int);
#if ZIME_PROBE_ENABLE_CPP_INTERPOSE
typedef int (*cpp_dc_channel_data_received_fn)(void *, long, long, const char *, unsigned int);
typedef void (*cpp_dc_channel_created_fn)(void *, long, unsigned long, int, int, int);
typedef void (*cpp_dc_channel_destroyed_fn)(void *, long, int, int);
typedef void (*cpp_dc_stream_created_fn)(void *, long, long, int, int);
typedef void (*cpp_dc_stream_destroyed_fn)(void *, long, long, int, int);
typedef void (*cpp_dc_channel_stream_blocked_fn)(void *, long, long, unsigned char, unsigned int);
typedef int (*cpp_transport_batch_send_fn)(void *, const void *, unsigned long);
#endif

static pthread_mutex_t wrapper_mutex = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t original_transport_table[8] = {0};
static uintptr_t wrapped_transport_table[8] = {0};
static uintptr_t original_callback_table[8] = {0};
static uintptr_t wrapped_callback_table[8] = {0};

#if ZIME_PROBE_ENABLE_CPP_INTERPOSE
static uintptr_t cpp_original_table(const void *self) {
  uintptr_t table = 0;
  if (self) memcpy(&table, (const unsigned char *)self + sizeof(uintptr_t), sizeof(table));
  return table;
}

static uintptr_t cpp_original_slot(const void *self, int slot) {
  uintptr_t table = cpp_original_table(self);
  uintptr_t value = 0;
  if (table && slot >= 0 && slot < 8) {
    memcpy(&value, (const unsigned char *)table + ((size_t)slot * sizeof(uintptr_t)), sizeof(value));
  }
  return value;
}

static int cpp_callback_logging_enabled(void) {
  return wrap_callbacks_enabled();
}

static void log_cpp_callback_event(const char *fn, int slot, void *self, long channel_id, long stream_id, int ret) {
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"%s\","
      "\"slot\":%d,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
      "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"streamId\":%ld,\"ret\":%d",
      fn, slot, self, (unsigned long)cpp_original_table(self),
      (unsigned long)cpp_original_slot(self, slot), channel_id, stream_id, ret);
}

int cpp_dc_on_channel_data_received(void *self, long channel_id, long stream_id, const char *buf, unsigned int len)
    __asm__("_ZN15DCCallbackImplC21OnChannelDataReceivedEllPKcj");
int cpp_dc_on_channel_data_received(void *self, long channel_id, long stream_id, const char *buf, unsigned int len) {
  cpp_dc_channel_data_received_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC21OnChannelDataReceivedEllPKcj", cpp_dc_channel_data_received_fn);
  int ret = -1;
  if (real) {
    ret = real(self, channel_id, stream_id, buf, len);
  } else {
    zime_channel_data_received_cb_fn original = (zime_channel_data_received_cb_fn)cpp_original_slot(self, 0);
    if (original) ret = original(channel_id, stream_id, buf, len);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_callback_buffer_event("DCCallbackImplC::OnChannelDataReceived", "receive", 0, channel_id, stream_id, buf, len, ret);
    log_cpp_callback_event("DCCallbackImplC::OnChannelDataReceived", 0, self, channel_id, stream_id, ret);
  }
  errno = saved;
  return ret;
}

void cpp_dc_on_channel_created(void *self, long channel_id, unsigned long value, int status, int err, int protocol)
    __asm__("_ZN15DCCallbackImplC16OnChannelCreatedElmii16E_ZIMEDCProtocol");
void cpp_dc_on_channel_created(void *self, long channel_id, unsigned long value, int status, int err, int protocol) {
  cpp_dc_channel_created_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC16OnChannelCreatedElmii16E_ZIMEDCProtocol", cpp_dc_channel_created_fn);
  if (real) {
    real(self, channel_id, value, status, err, protocol);
  } else {
    zime_channel_created_cb_fn original = (zime_channel_created_cb_fn)cpp_original_slot(self, 1);
    if (original) original(channel_id, value, status, err, protocol);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"DCCallbackImplC::OnChannelCreated\","
        "\"slot\":1,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"value\":%lu,"
        "\"status\":%d,\"err\":%d,\"protocol\":%d",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 1),
        channel_id, value, status, err, protocol);
  }
  errno = saved;
}

void cpp_dc_on_channel_destroyed(void *self, long channel_id, int status, int err)
    __asm__("_ZN15DCCallbackImplC18OnChannelDestroyedElii");
void cpp_dc_on_channel_destroyed(void *self, long channel_id, int status, int err) {
  cpp_dc_channel_destroyed_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC18OnChannelDestroyedElii", cpp_dc_channel_destroyed_fn);
  if (real) {
    real(self, channel_id, status, err);
  } else {
    zime_channel_destroyed_cb_fn original = (zime_channel_destroyed_cb_fn)cpp_original_slot(self, 2);
    if (original) original(channel_id, status, err);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"DCCallbackImplC::OnChannelDestroyed\","
        "\"slot\":2,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"status\":%d,\"err\":%d",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 2),
        channel_id, status, err);
  }
  errno = saved;
}

void cpp_dc_on_stream_created(void *self, long channel_id, long stream_id, int status, int err)
    __asm__("_ZN15DCCallbackImplC15OnStreamCreatedEllii");
void cpp_dc_on_stream_created(void *self, long channel_id, long stream_id, int status, int err) {
  cpp_dc_stream_created_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC15OnStreamCreatedEllii", cpp_dc_stream_created_fn);
  if (real) {
    real(self, channel_id, stream_id, status, err);
  } else {
    zime_channel_created_cb_fn original = (zime_channel_created_cb_fn)cpp_original_slot(self, 3);
    if (original) original(channel_id, (unsigned long)stream_id, status, err, 0);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"DCCallbackImplC::OnStreamCreated\","
        "\"slot\":3,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"streamId\":%ld,"
        "\"status\":%d,\"err\":%d",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 3),
        channel_id, stream_id, status, err);
  }
  errno = saved;
}

void cpp_dc_on_stream_destroyed(void *self, long channel_id, long stream_id, int status, int err)
    __asm__("_ZN15DCCallbackImplC17OnStreamDestroyedEllii");
void cpp_dc_on_stream_destroyed(void *self, long channel_id, long stream_id, int status, int err) {
  cpp_dc_stream_destroyed_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC17OnStreamDestroyedEllii", cpp_dc_stream_destroyed_fn);
  if (real) {
    real(self, channel_id, stream_id, status, err);
  } else {
    zime_channel_created_cb_fn original = (zime_channel_created_cb_fn)cpp_original_slot(self, 4);
    if (original) original(channel_id, (unsigned long)stream_id, status, err, 0);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"DCCallbackImplC::OnStreamDestroyed\","
        "\"slot\":4,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"streamId\":%ld,"
        "\"status\":%d,\"err\":%d",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 4),
        channel_id, stream_id, status, err);
  }
  errno = saved;
}

void cpp_dc_on_channel_stream_blocked(void *self, long channel_id, long stream_id, unsigned char blocked, unsigned int reason)
    __asm__("_ZN15DCCallbackImplC22OnChannelStreamBlockedEllbj");
void cpp_dc_on_channel_stream_blocked(void *self, long channel_id, long stream_id, unsigned char blocked, unsigned int reason) {
  cpp_dc_channel_stream_blocked_fn real = REAL_FN_ONCE("_ZN15DCCallbackImplC22OnChannelStreamBlockedEllbj", cpp_dc_channel_stream_blocked_fn);
  if (real) {
    real(self, channel_id, stream_id, blocked, reason);
  } else {
    zime_channel_stream_blocked_cb_fn original = (zime_channel_stream_blocked_cb_fn)cpp_original_slot(self, 5);
    if (original) original(channel_id, stream_id, blocked, reason);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"DCCallbackImplC::OnChannelStreamBlocked\","
        "\"slot\":5,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"channelId\":%ld,\"streamId\":%ld,"
        "\"blocked\":%u,\"reason\":%u",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 5),
        channel_id, stream_id, (unsigned)blocked, reason);
  }
  errno = saved;
}

int cpp_transport_on_send_data_batch(void *self, const void *packet_specs, unsigned long count)
    __asm__("_ZN19TransportBatchImplC16OnSendData_BatchEPK17ZIMEPacketOutSpecm");
int cpp_transport_on_send_data_batch(void *self, const void *packet_specs, unsigned long count) {
  cpp_transport_batch_send_fn real = REAL_FN_ONCE("_ZN19TransportBatchImplC16OnSendData_BatchEPK17ZIMEPacketOutSpecm", cpp_transport_batch_send_fn);
  int ret = -1;
  if (real) {
    ret = real(self, packet_specs, count);
  } else {
    zime_transport_batch_cb_fn original = (zime_transport_batch_cb_fn)cpp_original_slot(self, 1);
    if (original) ret = original(packet_specs, (size_t)count);
  }
  int saved = errno;
  if (cpp_callback_logging_enabled()) {
    size_t requested = count > 16 ? 16 : (size_t)count;
    requested *= ZIME_PACKET_OUT_SPEC_SIZE;
    log_memory_snapshot("TransportBatchImplC::OnSendData_Batch", "packet_specs", packet_specs, requested);
    log_zime_packet_specs("TransportBatchImplC::OnSendData_Batch", packet_specs, (size_t)count);
    log_line(
        "\"event\":\"zime_callback\",\"function\":\"TransportBatchImplC::OnSendData_Batch\","
        "\"slot\":1,\"self\":\"%p\",\"originalTable\":\"0x%lx\","
        "\"originalSlot\":\"0x%lx\",\"packetSpecs\":\"%p\",\"count\":%lu,\"ret\":%d",
        self, (unsigned long)cpp_original_table(self), (unsigned long)cpp_original_slot(self, 1),
        packet_specs, count, ret);
  }
  errno = saved;
  return ret;
}
#endif

static int wrapped_transport_send_cb(void *socket_param, long channel_id, const void *buf, unsigned int len) {
  zime_transport_send_cb_fn original = (zime_transport_send_cb_fn)original_transport_table[0];
  int ret = original ? original(socket_param, channel_id, buf, len) : -1;
  int saved = errno;
  log_callback_buffer_event("ZIMETransport.OnSendData", "send", 0, channel_id, -1, buf, len, ret);
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"ZIMETransport.OnSendData\","
      "\"slot\":0,\"socketParam\":\"%p\",\"channelId\":%ld,\"len\":%u,\"ret\":%d",
      socket_param, channel_id, len, ret);
  errno = saved;
  return ret;
}

static int wrapped_transport_batch_cb(const void *packet_specs, size_t count) {
  zime_transport_batch_cb_fn original = (zime_transport_batch_cb_fn)original_transport_table[1];
  int ret = original ? original(packet_specs, count) : -1;
  int saved = errno;
  size_t requested = count > 16 ? 16 : count;
  requested *= ZIME_PACKET_OUT_SPEC_SIZE;
  log_memory_snapshot("ZIMETransport.OnSendData_Batch", "packet_specs", packet_specs, requested);
  log_zime_packet_specs("ZIMETransport.OnSendData_Batch", packet_specs, count);
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"ZIMETransport.OnSendData_Batch\","
      "\"slot\":1,\"packetSpecs\":\"%p\",\"count\":%zu,\"ret\":%d",
      packet_specs, count, ret);
  errno = saved;
  return ret;
}

static int wrapped_channel_data_received_cb(long channel_id, long stream_id, const void *buf, unsigned int len) {
  zime_channel_data_received_cb_fn original = (zime_channel_data_received_cb_fn)original_callback_table[0];
  int ret = original ? original(channel_id, stream_id, buf, len) : 0;
  int saved = errno;
  log_callback_buffer_event("ZIMECallback.OnChannelDataReceived", "receive", 0, channel_id, stream_id, buf, len, ret);
  errno = saved;
  return ret;
}

static void wrapped_channel_created_cb(long channel_id, unsigned long value, int status, int err, int protocol) {
  zime_channel_created_cb_fn original = (zime_channel_created_cb_fn)original_callback_table[1];
  if (original) original(channel_id, value, status, err, protocol);
  int saved = errno;
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"ZIMECallback.OnChannelCreated\","
      "\"slot\":1,\"channelId\":%ld,\"value\":%lu,\"status\":%d,\"err\":%d,\"protocol\":%d",
      channel_id, value, status, err, protocol);
  errno = saved;
}

static void wrapped_channel_destroyed_cb(long channel_id, int status, int err) {
  zime_channel_destroyed_cb_fn original = (zime_channel_destroyed_cb_fn)original_callback_table[2];
  if (original) original(channel_id, status, err);
  int saved = errno;
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"ZIMECallback.OnChannelDestroyed\","
      "\"slot\":2,\"channelId\":%ld,\"status\":%d,\"err\":%d",
      channel_id, status, err);
  errno = saved;
}

static void wrapped_channel_stream_blocked_cb(long channel_id, long stream_id, unsigned char blocked, unsigned int reason) {
  zime_channel_stream_blocked_cb_fn original = (zime_channel_stream_blocked_cb_fn)original_callback_table[5];
  if (original) original(channel_id, stream_id, blocked, reason);
  int saved = errno;
  log_line(
      "\"event\":\"zime_callback\",\"function\":\"ZIMECallback.OnChannelStreamBlocked\","
      "\"slot\":5,\"channelId\":%ld,\"streamId\":%ld,\"blocked\":%u,\"reason\":%u",
      channel_id, stream_id, (unsigned)blocked, reason);
  errno = saved;
}

static void *prepare_wrapped_transport_table(void *engine, void *transport) {
  if (!wrap_callbacks_enabled() || !transport) return transport;
  const uintptr_t *src = (const uintptr_t *)transport;
  pthread_mutex_lock(&wrapper_mutex);
  for (int i = 0; i < 8; i++) {
    original_transport_table[i] = src[i];
    wrapped_transport_table[i] = src[i];
  }
  if (original_transport_table[0]) wrapped_transport_table[0] = (uintptr_t)wrapped_transport_send_cb;
  if (original_transport_table[1]) wrapped_transport_table[1] = (uintptr_t)wrapped_transport_batch_cb;
  pthread_mutex_unlock(&wrapper_mutex);
  log_ptr_table("ZIME_SetDataExternalTransport.wrapped", engine, wrapped_transport_table, 0);
  log_line(
      "\"event\":\"zime_callback_wrap\",\"function\":\"ZIME_SetDataExternalTransport\","
      "\"engine\":\"%p\",\"originalTable\":\"%p\",\"wrappedTable\":\"%p\"",
      engine, transport, wrapped_transport_table);
  return wrapped_transport_table;
}

static void *prepare_wrapped_callback_table(void *engine, void *callback) {
  if (!wrap_callbacks_enabled() || !callback) return callback;
  const uintptr_t *src = (const uintptr_t *)callback;
  pthread_mutex_lock(&wrapper_mutex);
  for (int i = 0; i < 8; i++) {
    original_callback_table[i] = src[i];
    wrapped_callback_table[i] = src[i];
  }
  if (original_callback_table[0]) wrapped_callback_table[0] = (uintptr_t)wrapped_channel_data_received_cb;
  if (original_callback_table[1]) wrapped_callback_table[1] = (uintptr_t)wrapped_channel_created_cb;
  if (original_callback_table[2]) wrapped_callback_table[2] = (uintptr_t)wrapped_channel_destroyed_cb;
  if (original_callback_table[5]) wrapped_callback_table[5] = (uintptr_t)wrapped_channel_stream_blocked_cb;
  pthread_mutex_unlock(&wrapper_mutex);
  log_ptr_table("ZIME_SetDataChannelCallback.wrapped", engine, wrapped_callback_table, 0);
  log_line(
      "\"event\":\"zime_callback_wrap\",\"function\":\"ZIME_SetDataChannelCallback\","
      "\"engine\":\"%p\",\"originalTable\":\"%p\",\"wrappedTable\":\"%p\"",
      engine, callback, wrapped_callback_table);
  return wrapped_callback_table;
}

void *ZIME_CreateDataEngine(void) {
  create_engine_fn real = REAL_FN_ONCE("ZIME_CreateDataEngine", create_engine_fn);
  void *ret = real ? real() : NULL;
  log_line("\"event\":\"zime_call\",\"function\":\"ZIME_CreateDataEngine\",\"retPtr\":\"%p\"", ret);
  return ret;
}

int ZIME_Init(void *engine, void *param) {
  log_memory_snapshot("ZIME_Init", "param_before", param, max_struct_dump_bytes());
  log_zime_init_param("ZIME_Init", "param_before", param);
  init_fn real = REAL_FN_ONCE("ZIME_Init", init_fn);
  int ret = real ? real(engine, param) : ENOSYS;
  log_memory_snapshot("ZIME_Init", "param_after", param, max_struct_dump_bytes());
  log_zime_init_param("ZIME_Init", "param_after", param);
  log_line("\"event\":\"zime_call\",\"function\":\"ZIME_Init\",\"engine\":\"%p\",\"param\":\"%p\",\"ret\":%d", engine, param, ret);
  return ret;
}

int ZIME_SetDataChannelCallback(void *engine, void *callback) {
  log_memory_snapshot("ZIME_SetDataChannelCallback", "callback_table", callback, 8 * sizeof(uintptr_t));
  void *active_callback = prepare_wrapped_callback_table(engine, callback);
  set_ptr_fn real = REAL_FN_ONCE("ZIME_SetDataChannelCallback", set_ptr_fn);
  int ret = real ? real(engine, active_callback) : ENOSYS;
  log_ptr_table("ZIME_SetDataChannelCallback", engine, callback, ret);
  log_ptr_symbols("ZIME_SetDataChannelCallback", callback);
  return ret;
}

int ZIME_SetDataExternalTransport(void *engine, void *transport) {
  log_memory_snapshot("ZIME_SetDataExternalTransport", "transport_table", transport, 8 * sizeof(uintptr_t));
  void *active_transport = prepare_wrapped_transport_table(engine, transport);
  set_ptr_fn real = REAL_FN_ONCE("ZIME_SetDataExternalTransport", set_ptr_fn);
  int ret = real ? real(engine, active_transport) : ENOSYS;
  log_ptr_table("ZIME_SetDataExternalTransport", engine, transport, ret);
  log_ptr_symbols("ZIME_SetDataExternalTransport", transport);
  return ret;
}

int ZIME_CreateDataChannel(void *engine, void *context, long *channel_id) {
  log_memory_snapshot("ZIME_CreateDataChannel", "context_before", context, max_struct_dump_bytes());
  log_zime_channel_context("ZIME_CreateDataChannel", "context_before", context);
  create_channel_fn real = REAL_FN_ONCE("ZIME_CreateDataChannel", create_channel_fn);
  long before = channel_id ? *channel_id : 0;
  int ret = real ? real(engine, context, channel_id) : ENOSYS;
  long after = channel_id ? *channel_id : 0;
  log_memory_snapshot("ZIME_CreateDataChannel", "context_after", context, max_struct_dump_bytes());
  log_zime_channel_context("ZIME_CreateDataChannel", "context_after", context);
  log_memory_snapshot("ZIME_CreateDataChannel", "channel_id", channel_id, sizeof(long));
  log_line(
      "\"event\":\"zime_call\",\"function\":\"ZIME_CreateDataChannel\","
      "\"engine\":\"%p\",\"context\":\"%p\",\"channelBefore\":%ld,"
      "\"channelAfter\":%ld,\"ret\":%d",
      engine, context, before, after, ret);
  return ret;
}

int ZIME_CreateDataStream(void *engine, long channel_id, long *stream_id, void *param) {
  log_memory_snapshot("ZIME_CreateDataStream", "param_before", param, max_struct_dump_bytes());
  log_zime_stream_param("ZIME_CreateDataStream", "param_before", param);
  create_stream_fn real = REAL_FN_ONCE("ZIME_CreateDataStream", create_stream_fn);
  long before = stream_id ? *stream_id : 0;
  int ret = real ? real(engine, channel_id, stream_id, param) : ENOSYS;
  long after = stream_id ? *stream_id : 0;
  log_memory_snapshot("ZIME_CreateDataStream", "param_after", param, max_struct_dump_bytes());
  log_zime_stream_param("ZIME_CreateDataStream", "param_after", param);
  log_memory_snapshot("ZIME_CreateDataStream", "stream_id", stream_id, sizeof(long));
  log_line(
      "\"event\":\"zime_call\",\"function\":\"ZIME_CreateDataStream\","
      "\"engine\":\"%p\",\"channelId\":%ld,\"streamBefore\":%ld,"
      "\"streamAfter\":%ld,\"param\":\"%p\",\"ret\":%d",
      engine, channel_id, before, after, param, ret);
  return ret;
}

int ZIME_SendData(void *engine, long channel_id, long stream_id, const void *buf, unsigned int len) {
  zime_send_fn real = REAL_FN_ONCE("ZIME_SendData", zime_send_fn);
  int ret = real ? real(engine, channel_id, stream_id, buf, len) : ENOSYS;
  log_buffer_event("ZIME_SendData", "send", engine, channel_id, stream_id, buf, len, ret);
  return ret;
}

int ZIME_SendData2(void *engine, long channel_id, long stream_id, const void *buf, unsigned int len, void *profile) {
  zime_send2_fn real = REAL_FN_ONCE("ZIME_SendData2", zime_send2_fn);
  int ret = real ? real(engine, channel_id, stream_id, buf, len, profile) : ENOSYS;
  log_buffer_event("ZIME_SendData2", "send", engine, channel_id, stream_id, buf, len, ret);
  return ret;
}

int ZIME_ReceiveData(void *engine, void *socket_param, const void *buf, unsigned int len) {
  log_memory_snapshot("ZIME_ReceiveData", "socket_param", socket_param, max_struct_dump_bytes());
  log_zime_socket_param("ZIME_ReceiveData", "socket_param", socket_param);
  zime_recv_fn real = REAL_FN_ONCE("ZIME_ReceiveData", zime_recv_fn);
  int ret = real ? real(engine, socket_param, buf, len) : ENOSYS;
  log_buffer_event("ZIME_ReceiveData", "receive", engine, 0, 0, buf, len, ret);
  log_line("\"event\":\"zime_call\",\"function\":\"ZIME_ReceiveData\",\"engine\":\"%p\",\"socketParam\":\"%p\",\"len\":%u,\"ret\":%d", engine, socket_param, len, ret);
  return ret;
}

int ZIME_DataChannelProcess2(void *engine, long channel_id, unsigned int *events) {
  process2_fn real = REAL_FN_ONCE("ZIME_DataChannelProcess2", process2_fn);
  unsigned int before = events ? *events : 0;
  int ret = real ? real(engine, channel_id, events) : ENOSYS;
  unsigned int after = events ? *events : 0;
  log_line(
      "\"event\":\"zime_call\",\"function\":\"ZIME_DataChannelProcess2\","
      "\"engine\":\"%p\",\"channelId\":%ld,\"eventsBefore\":%u,"
      "\"eventsAfter\":%u,\"ret\":%d",
      engine, channel_id, before, after, ret);
  return ret;
}

int ZIME_DestroyDataChannel(void *engine, long channel_id) {
  destroy_channel_fn real = REAL_FN_ONCE("ZIME_DestroyDataChannel", destroy_channel_fn);
  int ret = real ? real(engine, channel_id) : ENOSYS;
  log_line("\"event\":\"zime_call\",\"function\":\"ZIME_DestroyDataChannel\",\"engine\":\"%p\",\"channelId\":%ld,\"ret\":%d", engine, channel_id, ret);
  return ret;
}

int ZIME_DestroyDataStream(void *engine, long channel_id, long stream_id) {
  destroy_stream_fn real = REAL_FN_ONCE("ZIME_DestroyDataStream", destroy_stream_fn);
  int ret = real ? real(engine, channel_id, stream_id) : ENOSYS;
  log_line("\"event\":\"zime_call\",\"function\":\"ZIME_DestroyDataStream\",\"engine\":\"%p\",\"channelId\":%ld,\"streamId\":%ld,\"ret\":%d", engine, channel_id, stream_id, ret);
  return ret;
}

#if ZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE
int socket(int domain, int type, int protocol) {
  socket_real_fn real = REAL_FN_ONCE("socket", socket_real_fn);
  int ret = -1;
  if (real) {
    ret = real(domain, type, protocol);
  } else {
    errno = ENOSYS;
  }
  int saved = errno;
  if (transport_capture_enabled()) {
    log_line(
        "\"event\":\"transport_socket\",\"function\":\"socket\","
        "\"fd\":%d,\"domain\":%d,\"type\":%d,\"protocol\":%d,"
        "\"ret\":%d,\"errno\":%d",
        ret, domain, type, protocol, ret, saved);
  }
  errno = saved;
  return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  bind_real_fn real = REAL_FN_ONCE("bind", bind_real_fn);
  int ret = -1;
  if (real) {
    ret = real(sockfd, addr, addrlen);
  } else {
    errno = ENOSYS;
  }
  int saved = errno;
  char requested[128];
  char local[128];
  sockaddr_text(addr, addrlen, requested, sizeof(requested));
  fd_local_text(sockfd, local, sizeof(local));
  if (transport_capture_enabled()) {
    log_line(
        "\"event\":\"transport_bind\",\"function\":\"bind\","
        "\"fd\":%d,\"requestedLocal\":\"%s\",\"local\":\"%s\","
        "\"ret\":%d,\"errno\":%d",
        sockfd, requested, local, ret, saved);
  }
  errno = saved;
  return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  connect_real_fn real = REAL_FN_ONCE("connect", connect_real_fn);
  int ret = -1;
  if (real) {
    ret = real(sockfd, addr, addrlen);
  } else {
    errno = ENOSYS;
  }
  int saved = errno;
  char remote[128];
  char local[128];
  char peer_after[128];
  sockaddr_text(addr, addrlen, remote, sizeof(remote));
  fd_local_text(sockfd, local, sizeof(local));
  fd_peer_text(sockfd, peer_after, sizeof(peer_after));
  if (transport_capture_enabled()) {
    log_line(
        "\"event\":\"transport_connect\",\"function\":\"connect\","
        "\"fd\":%d,\"remote\":\"%s\",\"local\":\"%s\","
        "\"peerAfter\":\"%s\",\"ret\":%d,\"errno\":%d",
        sockfd, remote, local, peer_after, ret, saved);
  }
  errno = saved;
  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  send_real_fn real = REAL_FN_ONCE("send", send_real_fn);
  ssize_t ret = real ? real(sockfd, buf, len, flags) : -1;
  int saved = errno;
  log_transport_buffer("send", "send", sockfd, buf, len, ret);
  errno = saved;
  return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  recv_real_fn real = REAL_FN_ONCE("recv", recv_real_fn);
  ssize_t ret = real ? real(sockfd, buf, len, flags) : -1;
  int saved = errno;
  log_transport_buffer("recv", "receive", sockfd, buf, len, ret);
  errno = saved;
  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest, socklen_t destlen) {
  sendto_real_fn real = REAL_FN_ONCE("sendto", sendto_real_fn);
  ssize_t ret = real ? real(sockfd, buf, len, flags, dest, destlen) : -1;
  int saved = errno;
  log_transport_buffer_ex("sendto", "send", sockfd, buf, len, ret, dest, destlen);
  errno = saved;
  return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src, socklen_t *srclen) {
  recvfrom_real_fn real = REAL_FN_ONCE("recvfrom", recvfrom_real_fn);
  ssize_t ret = real ? real(sockfd, buf, len, flags, src, srclen) : -1;
  int saved = errno;
  log_transport_buffer_ex("recvfrom", "receive", sockfd, buf, len, ret, src, srclen ? *srclen : 0);
  errno = saved;
  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  sendmsg_real_fn real = REAL_FN_ONCE("sendmsg", sendmsg_real_fn);
  ssize_t ret = real ? real(sockfd, msg, flags) : -1;
  int saved = errno;
  log_msg_buffer("sendmsg", "send", sockfd, msg, ret);
  errno = saved;
  return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  recvmsg_real_fn real = REAL_FN_ONCE("recvmsg", recvmsg_real_fn);
  ssize_t ret = real ? real(sockfd, msg, flags) : -1;
  int saved = errno;
  log_msg_buffer("recvmsg", "receive", sockfd, msg, ret);
  errno = saved;
  return ret;
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  sendmmsg_real_fn real = REAL_FN_ONCE("sendmmsg", sendmmsg_real_fn);
  int ret = -1;
  if (real) {
    ret = real(sockfd, msgvec, vlen, flags);
  } else {
    errno = ENOSYS;
  }
  int saved = errno;
  if (ret > 0 && msgvec) {
    for (int i = 0; i < ret; i++) {
      log_msg_buffer("sendmmsg", "send", sockfd, &msgvec[i].msg_hdr, (ssize_t)msgvec[i].msg_len);
    }
  }
  errno = saved;
  return ret;
}

int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
  recvmmsg_real_fn real = REAL_FN_ONCE("recvmmsg", recvmmsg_real_fn);
  int ret = -1;
  if (real) {
    ret = real(sockfd, msgvec, vlen, flags, timeout);
  } else {
    errno = ENOSYS;
  }
  int saved = errno;
  if (ret > 0 && msgvec) {
    for (int i = 0; i < ret; i++) {
      log_msg_buffer("recvmmsg", "receive", sockfd, &msgvec[i].msg_hdr, (ssize_t)msgvec[i].msg_len);
    }
  }
  errno = saved;
  return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
  read_real_fn real = REAL_FN_ONCE("read", read_real_fn);
  ssize_t ret = real ? real(fd, buf, count) : -1;
  int saved = errno;
  log_transport_buffer("read", "receive", fd, buf, count, ret);
  errno = saved;
  return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
  write_real_fn real = REAL_FN_ONCE("write", write_real_fn);
  ssize_t ret = real ? real(fd, buf, count) : -1;
  int saved = errno;
  log_transport_buffer("write", "send", fd, buf, count, ret);
  errno = saved;
  return ret;
}

int SSL_write(void *ssl, const void *buf, int num) {
  ssl_write_real_fn real = REAL_FN_ONCE("SSL_write", ssl_write_real_fn);
  int ret = real ? real(ssl, buf, num) : -1;
  int saved = errno;
  log_ssl_buffer("SSL_write", "send", ssl, buf, num, ret);
  errno = saved;
  return ret;
}

int SSL_read(void *ssl, void *buf, int num) {
  ssl_read_real_fn real = REAL_FN_ONCE("SSL_read", ssl_read_real_fn);
  int ret = real ? real(ssl, buf, num) : -1;
  int saved = errno;
  log_ssl_buffer("SSL_read", "receive", ssl, buf, num, ret);
  errno = saved;
  return ret;
}
#endif
