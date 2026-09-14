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

static int unlink_failed;
static int fsync_failed;

static void record_event(const char *event) {
    const char *path = getenv("PM_INTERPOSE_LOG");
    if (path == NULL) return;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return;
    (void)syscall(SYS_write, fd, event, strlen(event));
    (void)syscall(SYS_close, fd);
}

static int exact_target(const char *actual, const char *variable) {
    const char *expected = getenv(variable);
    return actual != NULL && expected != NULL && strcmp(actual, expected) == 0;
}

int unlink(const char *path) {
    static int (*real_unlink)(const char *);
    if (real_unlink == NULL) real_unlink = dlsym(RTLD_NEXT, "unlink");
    if (!unlink_failed && exact_target(path, "PM_FAIL_UNLINK_PATH")) {
        unlink_failed = 1;
        record_event("unlink\n");
        errno = EIO;
        return -1;
    }
    return real_unlink(path);
}

int unlinkat(int directory, const char *path, int flags) {
    static int (*real_unlinkat)(int, const char *, int);
    if (real_unlinkat == NULL) real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
    if (!unlink_failed && path[0] == '/' && exact_target(path, "PM_FAIL_UNLINK_PATH")) {
        unlink_failed = 1;
        record_event("unlink\n");
        errno = EIO;
        return -1;
    }
    return real_unlinkat(directory, path, flags);
}

int fsync(int fd) {
    static int (*real_fsync)(int);
    if (real_fsync == NULL) real_fsync = dlsym(RTLD_NEXT, "fsync");
    char link[64];
    char path[PATH_MAX + 1];
    int length = snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t count = length > 0 ? readlink(link, path, PATH_MAX) : -1;
    if (count >= 0) path[count] = '\0';
    if (!fsync_failed && count >= 0 && exact_target(path, "PM_FAIL_FSYNC_PATH")) {
        fsync_failed = 1;
        record_event("fsync\n");
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}
