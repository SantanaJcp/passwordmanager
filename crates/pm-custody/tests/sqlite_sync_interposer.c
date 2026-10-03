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
#include <signal.h>

static unsigned long calls;

static int observe(int fd, const char *operation, int writing) {
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
    const char *selected = getenv("PM28_SYNC_OPERATION");
    if (selected != NULL && strcmp(selected, writing ? "write" : "sync") != 0) return 0;
    if (selected == NULL && writing) return 0;
    unsigned long ordinal = __sync_add_and_fetch(&calls, 1);
    const char *fail = getenv("PM28_SYNC_FAIL");
    if (fail == NULL || (strcmp(fail, "0") != 0 && strcmp(fail, "1") != 0)) _exit(120);
    const char *index = getenv("PM28_SYNC_INDEX");
    char *end = NULL;
    unsigned long chosen = index == NULL ? 1 : strtoul(index, &end, 10);
    if (index != NULL && (end == index || *end != '\0' || chosen == 0)) _exit(120);
    const char *failure = getenv("PM28_SYNC_ERRNO");
    const char *arm = getenv("PM28_SYNC_ARM");
    char armed_error[8];
    unsigned int armed_failure = 0;
    int armed_pause = 0;
    if (arm != NULL) {
        FILE *control = fopen(arm, "r");
        if (control == NULL) _exit(120);
        int fields = fscanf(control, "%lu %7s %u", &chosen, armed_error, &armed_failure);
        if (fclose(control) != 0 || fields != 3 || armed_failure > 1) _exit(120);
        failure = armed_error;
        armed_pause = chosen != 0 && ordinal == chosen;
    }
    int injected = ordinal == chosen && (arm == NULL ? strcmp(fail, "1") == 0 : armed_failure == 1);
    char event[128];
    int size = snprintf(event, sizeof(event), "pid=%ld op=%s count=%lu injected=%d\n", pid, operation, ordinal, injected);
    if (size <= 0 || (size_t)size >= sizeof(event)) _exit(120);
    int log = (int)syscall(SYS_openat, AT_FDCWD, log_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (log < 0 || syscall(SYS_write, log, event, (size_t)size) != size || syscall(SYS_close, log) != 0) _exit(120);
    const char *pause = getenv("PM28_SYNC_PAUSE");
    if (armed_pause || (pause != NULL && (strcmp(pause, "all") == 0 || ordinal == chosen))) {
        if (raise(SIGSTOP) != 0) _exit(120);
    }
    if (injected) {
        if (failure == NULL || strcmp(failure, "EIO") == 0) errno = EIO;
        else if (strcmp(failure, "ENOSPC") == 0) errno = ENOSPC;
        else _exit(120);
    }
    return injected;
}

int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    if (real == NULL) _exit(120);
    if (observe(fd, "fsync", 0)) return -1;
    return real(fd);
}

int fdatasync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fdatasync");
    if (real == NULL) _exit(120);
    if (observe(fd, "fdatasync", 0)) return -1;
    return real(fd);
}

ssize_t pwrite64(int fd, const void *bytes, size_t length, off64_t offset) {
    ssize_t (*real)(int, const void *, size_t, off64_t) = dlsym(RTLD_NEXT, "pwrite64");
    if (real == NULL) _exit(120);
    if (observe(fd, "pwrite64", 1)) return -1;
    return real(fd, bytes, length, offset);
}

ssize_t pwrite(int fd, const void *bytes, size_t length, off_t offset) {
    ssize_t (*real)(int, const void *, size_t, off_t) = dlsym(RTLD_NEXT, "pwrite");
    if (real == NULL) _exit(120);
    if (observe(fd, "pwrite", 1)) return -1;
    return real(fd, bytes, length, offset);
}
