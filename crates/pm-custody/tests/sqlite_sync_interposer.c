// SPDX-License-Identifier: AGPL-3.0-only
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static unsigned long calls;

static int observe(int fd, const char *operation) {
    const char *target = getenv("PM28_SYNC_TARGET");
    const char *pid_path = getenv("PM28_SYNC_PID");
    const char *log_path = getenv("PM28_SYNC_LOG");
    if (target == NULL || pid_path == NULL || log_path == NULL) _exit(120);
    char link[64], actual[PATH_MAX + 1];
    int length = snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    if (length <= 0 || (size_t)length >= sizeof(link)) _exit(120);
    ssize_t count = readlink(link, actual, PATH_MAX);
    if (count < 0) _exit(120);
    actual[count] = '\0';
    if (strcmp(actual, target) != 0) return 0;
    FILE *pid_file = fopen(pid_path, "r");
    if (pid_file == NULL) _exit(120);
    long pid;
    int parsed = fscanf(pid_file, "%ld", &pid);
    if (fclose(pid_file) != 0 || parsed != 1 || pid != (long)getpid()) _exit(120);
    ++calls;
    const char *fail = getenv("PM28_SYNC_FAIL");
    if (fail == NULL || (strcmp(fail, "0") != 0 && strcmp(fail, "1") != 0)) _exit(120);
    int injected = calls == 1 && strcmp(fail, "1") == 0;
    char event[128];
    int size = snprintf(event, sizeof(event), "pid=%ld op=%s count=%lu injected=%d\n", pid, operation, calls, injected);
    if (size <= 0 || (size_t)size >= sizeof(event)) _exit(120);
    int log = (int)syscall(SYS_openat, AT_FDCWD, log_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (log < 0 || syscall(SYS_write, log, event, (size_t)size) != size || syscall(SYS_close, log) != 0) _exit(120);
    if (injected) errno = EIO;
    return injected;
}

int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    if (real == NULL) _exit(120);
    if (observe(fd, "fsync")) return -1;
    return real(fd);
}

int fdatasync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fdatasync");
    if (real == NULL) _exit(120);
    if (observe(fd, "fdatasync")) return -1;
    return real(fd);
}
