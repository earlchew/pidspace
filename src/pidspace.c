/* -*- c-basic-offset:4; indent-tabs-mode:nil -*- vi: set sw=4 et: */
/*
// Copyright (c) 2022, Earl Chew
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the names of the authors of source code nor the names
//       of the contributors to the source code may be used to endorse or
//       promote products derived from this software without specific
//       prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL EARL CHEW BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/capability.h>
#include <sys/fsuid.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* -------------------------------------------------------------------------- */
#define ARRAYSIZE(x) (sizeof((x))/sizeof((x)[0]))

/* -------------------------------------------------------------------------- */
struct Tty {
    pid_t mPgid;
    int mFd;
};

struct Parent {
    struct {
        pid_t mPid;

        int mSyncRd;
        int mSyncWr;
    } mChild;
};

struct Child {
    char **mCmd;

    sigset_t mInheritedSet;

    struct {
        pid_t mPgid;
        pid_t mSid;

        int mSyncRd;
        int mSyncWr;
    } mParent;
};

struct Service {
    struct Parent mParent;
    struct Child mChild;
    struct Tty mTty;
};

/* -------------------------------------------------------------------------- */
#if __GLIBC__ < 2 || __GLIBC__ == 2 && __GLIBC_MINOR__ < 32
static const char *
sigabbrev_np(int aSigNo)
{
    const char *abbrev = 0;

    switch (aSigNo) {
    case SIGHUP:    abbrev = "HUP";    break;
    case SIGINT:    abbrev = "INT";    break;
    case SIGQUIT:   abbrev = "QUIT";   break;
    case SIGILL:    abbrev = "ILL";    break;
    case SIGTRAP:   abbrev = "TRAP";   break;
    case SIGABRT:   abbrev = "ABRT";   break;
    case SIGFPE:    abbrev = "FPE";    break;
    case SIGKILL:   abbrev = "KILL";   break;
    case SIGBUS:    abbrev = "BUS";    break;
    case SIGSYS:    abbrev = "SYS";    break;
    case SIGSEGV:   abbrev = "SEGV";   break;
    case SIGPIPE:   abbrev = "PIPE";   break;
    case SIGALRM:   abbrev = "ALRM";   break;
    case SIGTERM:   abbrev = "TERM";   break;
    case SIGURG:    abbrev = "URG";    break;
    case SIGSTOP:   abbrev = "STOP";   break;
    case SIGTSTP:   abbrev = "TSTP";   break;
    case SIGCONT:   abbrev = "CONT";   break;
    case SIGCHLD:   abbrev = "CHLD";   break;
    case SIGTTIN:   abbrev = "TTIN";   break;
    case SIGTTOU:   abbrev = "TTOU";   break;
    case SIGPOLL:   abbrev = "POLL";   break;
    case SIGXCPU:   abbrev = "XCPU";   break;
    case SIGXFSZ:   abbrev = "XFSZ";   break;
    case SIGVTALRM: abbrev = "VTALRM"; break;
    case SIGPROF:   abbrev = "PROF";   break;
    case SIGUSR1:   abbrev = "USR1";   break;
    case SIGUSR2:   abbrev = "USR2";   break;
    case SIGWINCH:  abbrev = "WINCH";  break;
    }

    return abbrev;
}
#endif

/* -------------------------------------------------------------------------- */
static void
die(const char *aFmt, ...)
{
    if (aFmt) {
        va_list argp;

        va_start(argp, aFmt);
        if (errno)
            vwarn(aFmt, argp);
        else
            vwarnx(aFmt, argp);
        va_end(argp);
    }

    exit(127);
}

/* -------------------------------------------------------------------------- */
static int sDebug;
static long sPPid;

static struct option sOptions[] = {
   { "debug", no_argument,       0,  'd' },
   { "ppid",  required_argument, 0,  'P' },
};

/* -------------------------------------------------------------------------- */
static struct timespec sEpoch;

static void
debug_(unsigned aLineNo, const char *aFmt, ...)
{
    static char *debugBufPtr;
    static size_t debugBufLen;

    static FILE *debugFile;

    if (!debugFile) {
        debugFile = open_memstream(&debugBufPtr, &debugBufLen);
        if (!debugFile)
            die("Unable to create debug stream");
    }

    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time))
        die("Unable to read clock");

    long milliseconds =
        (time.tv_sec - sEpoch.tv_sec) * 1000 +
        (time.tv_nsec - sEpoch.tv_nsec) / 1000000;

    long minutes = milliseconds / (60 * 1000);
    milliseconds %= (60 * 1000);

    long seconds = milliseconds / 1000;
    milliseconds %= 1000;

    va_list argp;

    va_start(argp, aFmt);

    fprintf(debugFile, "%s: [%ld:%02ld.%03ld] %d %u - ",
        program_invocation_short_name,
        minutes, seconds, milliseconds,
        getpid(), aLineNo);

    vfprintf(debugFile, aFmt, argp);
    fputc('\n', debugFile);

    fflush(debugFile);

    fwrite(debugBufPtr, debugBufLen, 1, stderr);

    rewind(debugFile);

    va_end(argp);
}

#define DEBUG(...) \
    if (!sDebug) ; else do debug_(__LINE__, __VA_ARGS__); while (0)

/* -------------------------------------------------------------------------- */
static void
usage(void)
{
    fprintf(
        stderr,
        "usage: %s [--debug] [--ppid PPID] -- cmd ...\n",
        program_invocation_short_name);
    die(0);
}

/* -------------------------------------------------------------------------- */
static long
strtowhole(const char *aString)
{
    int rc = -1;

    long number = 0;

    if (isdigit((unsigned char) *aString)) {

        char *endPtr;

        errno = 0;
        number = strtol(aString, &endPtr, 10);

        if ('0' == *aString) {
            const char *lastPtr = endPtr;

            if (1 != lastPtr - aString)
                errno = EINVAL;
        }

        if (!*endPtr && !errno)
            rc = 0;
    }

    return rc ? -1 : number;
}

/* -------------------------------------------------------------------------- */
static void
verify_privileged_role()
{
    cap_flag_value_t capValue;

    cap_t capSet = cap_get_proc();
    if (!capSet)
        die("Unable to query process capabilities");

    if (cap_get_flag(capSet, CAP_SYS_ADMIN, CAP_PERMITTED, &capValue))
        die("Unable to query process CAP_SYS_ADMIN");

    if (CAP_CLEAR != capValue) {

        cap_value_t setCaps[] = { CAP_SYS_ADMIN };

        if (cap_set_flag(
                    capSet, CAP_EFFECTIVE,
                    ARRAYSIZE(setCaps), setCaps, CAP_SET))
            die("Unable to set process CAP_SYS_ADMIN");

    } else {

        uid_t euid = geteuid();

        if (0 != euid) {
            struct passwd *passwd = getpwuid(euid);

            if (passwd)
                die("Expected CAP_SYS_ADMIN or root instead of %s",
                    passwd->pw_name);
            else
                die("Expected CAP_SYS_ADMIN or root instead of uid %d", euid);
        }
    }

    cap_free(capSet);
}

/* -------------------------------------------------------------------------- */
static pid_t
foreground(int aTtyFd, int aPgid)
{
    pid_t fgPgid = 0;

    if (-1 != aTtyFd) {

        fgPgid = tcgetpgrp(aTtyFd);
        if (-1 == fgPgid)
            die("Unable to query foreground pgid");

        if (-1 != aPgid) {
            if (fgPgid != getpgrp()) {

                fgPgid = 0;

            } else {

                DEBUG("Foreground pgid %d", aPgid);

                if (tcsetpgrp(aTtyFd, aPgid))
                    die("Unable to configure foreground pgid %d", aPgid);
            }
        }
    }

    return fgPgid;
}

/* -------------------------------------------------------------------------- */
static pid_t
privileged(struct Service *aService, int argc, char **argv)
{
    /*****************************************************************
     * Place this function as close to the head of the source file   *
     * as possible to reduce the chance that it will call additional *
     * functions while running at elevated privilege.                *
     *****************************************************************/

    if (clock_gettime(CLOCK_MONOTONIC, &sEpoch))
        die("Unable to initialise clock");

    /* When run as setuid, glibc and musl ensure that stdin, stdout,
     * and stderr, are valid file descriptors open to /dev/null,
     * or /dev/full. Do the same here to cover the case where
     * the program is not run setuid.
     */

    static const char sDevNull[] = "/dev/null";
    static const char sDevFull[] = "/dev/full";

    if (-1 == dup2(STDIN_FILENO, STDIN_FILENO)) {
        if (EBADF != errno || STDIN_FILENO != open(sDevFull, O_RDONLY))
            die("Unable to initialise stdin");
    }

    if (-1 == dup2(STDOUT_FILENO, STDOUT_FILENO)) {
        if (EBADF != errno || STDOUT_FILENO != open(sDevNull, O_WRONLY))
            die("Unable to initialise stdout");
    }

    if (-1 == dup2(STDERR_FILENO, STDERR_FILENO)) {
        if (EBADF != errno || STDERR_FILENO != open(sDevNull, O_WRONLY))
            die("Unable to initialise stdout");
    }

    /* Either skip the first argument and point at the first
     * argument, or point at the trailing null pointer.
     *
     * http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2354.htm
     *
     *   - argv[argc] shall be a null pointer.
     */

    while (1) {
        int opt = getopt_long(argc, argv, "+dP:", sOptions, 0);
        if (-1 == opt)
            break;

        switch (opt) {
        case '?':
            usage();
            break;

        case 'd':
            sDebug =1;
            break;

        case 'P':
            {
                sPPid = strtowhole(optarg);

                pid_t ppid = sPPid;

                if (-1 == sPPid || ppid != sPPid)
                    die("Unable to parse parent pid %s", optarg);

                if (!sPPid)
                    die("Invalid parent pid %s", optarg);
                break;
            }
        }
    }

    if (optind >= argc)
        usage();

    aService->mChild.mCmd = &argv[optind];

    /* Use of CLONE_NEWPID, CLONE_NEWNS, and mount(2), require that the caller
     * be privileged, or have CAP_SYSADMIN capability.
     */

    verify_privileged_role();

    /* Use a pair of pipes to synchronise the prctl(2) actions in the child.
     * This is required because the child inhabits a new pid namespace,
     * resulting in its getppid(2) invocations always returning 0.
     *
     * The process running as pid 1 in the new namespace cannot be
     * terminated with a signal sent from within the new namespace
     * itself. Allow it to use a sync pipe to request the parent
     * to terminate it with a specific signal.
     */

    int childSync[2];
    if (pipe2(childSync, O_CLOEXEC))
        die("Unable to create child sync pipe");

    int parentSync[2];
    if (pipe2(parentSync, O_CLOEXEC))
        die("Unable to create parent sync pipe");

    /* If not running as a session leader, find the controlling terminal,
     * and interrogate it for the foreground process group. The controlling
     * terminal is later used to determine if parent or child belong to
     * the foreground process group. The foreground process group is
     * recorded so that it can be restored on exit.
     *
     * The parent does not function as a job control shell, even if
     * running as a session leader. Because of this, ignore the controlling
     * terminal even if it exists. Presently no attempt is used to detach
     * from the controlling terminal using TIOCNOTTY.
     */

    pid_t selfPgid = getpgrp();
    pid_t selfSid = getsid(0);

    DEBUG("Process pgid %d sid %d", selfPgid, selfSid);

    pid_t fgPgid = 0;
    int ttyFd = -1;

    if (selfPgid != selfSid) {

        char *ttyName = ctermid(0);

        ttyFd = open(ttyName, O_RDONLY | O_CLOEXEC);
        if (-1 == ttyFd) {

            if (ENXIO != errno)
                die("Unable to open %s", ttyName);

        } else {

            fgPgid = foreground(ttyFd, -1);

            DEBUG(
                "Controlling terminal %s foreground pgid %d",
                ttyName, fgPgid);
        }
    }

    aService->mTty.mFd = ttyFd;
    aService->mTty.mPgid = fgPgid;

    /* Save the signal mask to be restored when running the command,
     * and block all signals until signal propagation is properly
     * configured.
     */

    sigset_t fillSet;

    if (sigfillset(&fillSet))
        die("Unable to initialise blocking signal set");

    if (sigprocmask(SIG_BLOCK, &fillSet, &aService->mChild.mInheritedSet))
        die("Unable to configure blocking signal set");

    /* After blocking SIGCHLD so as not to miss any deliveries, reap any
     * zombie children transferred across the execve(2) that started this
     * program. Children that become zombies later will be noticed via SIGCHLD.
     */

    pid_t zombiePid;
    do {

        zombiePid = waitpid(0, 0, WNOHANG);
        if (-1 == zombiePid) {
            if (ECHILD != errno)
                die("Unable to reap zombie children");

            zombiePid = 0;
        }

        if (zombiePid)
            DEBUG("Zombie pid %d", zombiePid);

    } while (zombiePid);

    /* Fork the child process in a new pid namespace. Remember that
     * CLONE_NEWPID affects subsequent fork(2), and does not change
     * the pid namespace of the caller.
     */

    if (unshare(CLONE_NEWPID))
        die("Unable to unshare pid namespace");

    pid_t childPid = fork();
    if (-1 == childPid)
        die("Unable to fork child");

    if (childPid) {

        if (setpgid(childPid, childPid))
            die("Unable to configure pgid %d", childPid);

        aService->mParent.mChild.mPid = childPid;

        aService->mParent.mChild.mSyncRd = childSync[0];
        aService->mParent.mChild.mSyncWr = parentSync[1];

        close(childSync[1]);
        close(parentSync[0]);

    } else {

        aService->mChild.mParent.mSyncWr = childSync[1];
        aService->mChild.mParent.mSyncRd = parentSync[0];
        aService->mChild.mParent.mPgid = selfPgid;
        aService->mChild.mParent.mSid = selfSid;

        close(childSync[0]);
        close(parentSync[1]);

        /* The child process inherits the controlling terminal of its
         * parent. Place the child process in its own process group
         * so that it will only receive signals purposefully sent
         * from the parent.
         */

        if (setpgid(0, 0))
            die("Unable to configure pgid %d", getpid());

        /* Mount a new /proc in a new mount namespace to reflect the
         * new pid namespace. Constrain the propagation to avoid affecting
         * the mount points in the parent namespace.
         */

        if (unshare(CLONE_NEWNS))
            die("Unable to unshare mount namespace");

        const char procMount[] = "/proc";
        const char procFS[] = "proc";

        if (mount(0, procMount, 0, MS_REC|MS_PRIVATE, 0))
            die("Unable to change proc filesystem propagation");

        if (mount(0, procMount, procFS, MS_NOSUID|MS_NOEXEC|MS_NODEV, 0))
            die("Unable to mount /proc");
    }

    return childPid;
}

/* -------------------------------------------------------------------------- */
static void
pdeathsig(pid_t aParentPid)
{
    int killSig;

    if (-1 == aParentPid) {

        if (prctl(PR_GET_PDEATHSIG, &killSig, 0, 0, 0))
            die("Unable to get pdeathsig");

        if (!killSig)
            die("Unconfigured pdeathsig");

    } else {

        killSig = SIGKILL;

        if (prctl(PR_SET_PDEATHSIG, killSig, 0, 0, 0))
            die("Unable to set pdeathsig");

        if (!aParentPid || getppid() == aParentPid)
            killSig = 0;
    }

    /* When killed from its own pid namespace, only those signals that
     * are handled will be delivered by the kernel the init pid 1 process.
     * This means that signals that are set to SIG_DFL will not be delivered,
     * and consequentially there is no way for the init pid 1 process to
     * terminate itself with any signal.
     *
     * Since this function is only called when PDEATHSIG was set too late,
     * and the parent has already terminated, the exit status is likely
     * not very interesting to any reaper. Thus it is is not vital to
     * duplicate the termination signal, and a simple exit(3) suffices.
     *
     * The same reasoning applies to all other cases where the child loses
     * the parent before PDEATHSIG is configured.
     */

    if (killSig)
        exit(128 + killSig);
}

/* -------------------------------------------------------------------------- */
static int
read_byte(int aFd)
{
    int byte = -1;

    char buf[1];
    ssize_t readBytes = read(aFd, buf, 1);

    if (-1 != readBytes) {
        if (readBytes)
            byte = (unsigned char) buf[0];
        else
            errno = 0;
    }

    /* Return the non-negative byte, or -1 with zero errno
     * to indicate eof, and a non-zero errno for other error cases.
     */

    return byte;
}

/* -------------------------------------------------------------------------- */
static int
wait_child(int aFd)
{
    return read_byte(aFd);
}

/* -------------------------------------------------------------------------- */
static void
dispatch_parent(int aFd, int aSignal)
{
    while (1) {

        /* Write a single byte to allow the parent to recognise
         * the synchronisation state from the child.
         */

        char buf[1] = { aSignal };

        ssize_t wroteBytes = write(aFd, buf, 1);

        if (wroteBytes)
            break;

        if (-1 == wroteBytes) {
            if (EINTR != errno)
                die("Unable to dispatch parent");
        }
    }
}

/* -------------------------------------------------------------------------- */
static void
dispatch_child(int aFd)
{
    while (1) {

        /* Write a single byte to allow the child to differentiate
         * between two cases:
         *
         *   a. The parent terminates before writing
         *   b. The parent terminates after writing
         */

        char buf[1] = { 0 };

        ssize_t wroteBytes = write(aFd, buf, 1);

        if (wroteBytes)
            break;

        if (-1 == wroteBytes) {
            if (EPIPE == errno)
                break;
            if (EINTR != errno)
                die("Unable to dispatch child");
        }
    }
}

/* -------------------------------------------------------------------------- */
static int
wait_parent(int aFd)
{
    int parentReady = -1;

    /* Read a single byte from the parent to differentiate
     * between two cases:
     *
     *   a. The parent terminates before writing
     *   b. The parent terminates after writing
     */

    do
    {
        int readByte = read_byte(aFd);

        if (-1 == readByte) {

            if (EINTR != errno)
                break;

        } else {

            parentReady = readByte;
            break;

        }

    } while (-1 == parentReady);

    return parentReady;
}

/* -------------------------------------------------------------------------- */
static void
stop(int aSignal, int aSigWrFd, pid_t aPid, int aTtyFd)
{
    DEBUG("Stop %s", sigabbrev_np(aSignal));

    pid_t selfPid = getpid();

    int stopSig = aSignal;
    int contSig = SIGCONT;

    if (-1 == aSigWrFd) {

        /* The parent process should stop when it detects the child
         * stopping, and this should only occur after the child has
         * requested that it be stopped. When this occurs, the parent
         * should use SIGSTOP to stop the child, and then react to
         * child stopping.
         */

        if (SIGSTOP != stopSig)
            die("Unexpected stop %s", sigabbrev_np(stopSig));

        if (kill(selfPid, stopSig))
            die("Unable to kill pid %d using %s",
                selfPid, sigabbrev_np(stopSig));

        /* The process will be suspended at this point until continued.
         * When continued, execution will restart, and SIGCONT queued
         * for processing.
         */

    } else {

        DEBUG("Dispatch %s", sigabbrev_np(stopSig));

        dispatch_parent(aSigWrFd, stopSig);

        /* The process willl be stopped by its parent. Eventually
         * the parent will will also send SIGCONT to restart
         * the process. Use sigwaitinfo(2) to detect the SIGCONT
         * sent by the parent.
         */

        sigset_t contSigSet;

        if (sigemptyset(&contSigSet))
            die("Unable to initialise continuation signal set");

        if (sigaddset(&contSigSet, contSig))
            die("Unable to exclude %s from continuation signal set",
                sigabbrev_np(contSig));

        DEBUG("Waiting for %s", sigabbrev_np(contSig));

        while (-1 == sigwaitinfo(&contSigSet, 0)) {
            if (EINTR != errno)
                die("Unable to continue pid %d using %s",
                    selfPid, sigabbrev_np(contSig));
        }

        /* Before processing SIGCONT, set the foreground
         * process group if configured to avoid missing
         * any job control signals.
         */

        foreground(aTtyFd, aPid);

        /* The SIGCONT sent by the parent is no longer pending, and
         * is no longer queued for processing. Since the signal
         * is considered delivered, handle it here by sending it
         * to the child process group.
         */

        DEBUG("Waking pgid %d with %s", aPid, sigabbrev_np(contSig));

        if (killpg(aPid, contSig)) {
            if (ESRCH != errno)
                die("Unable to resume process %d", aPid);
        }
    }
}

/* -------------------------------------------------------------------------- */
static void
terminate(int aSigWrFd, int aSignal)
{
    DEBUG("Terminate %s", sigabbrev_np(aSignal));

    pid_t selfPid = getpid();

    sigset_t sigSet;

    if (sigprocmask(SIG_SETMASK, 0, &sigSet))
        die("Unable to query signal mask");

    if (sigdelset(&sigSet, aSignal))
        die("Unable to remove %s from signal mask", sigabbrev_np(aSignal));

    if (SIGKILL != aSignal && SIGSTOP != aSignal) {
        if (SIG_ERR == signal(aSignal, SIG_DFL))
            die("Unable to reconfigure handler for %s", sigabbrev_np(aSignal));
    }

    if (sigprocmask(SIG_SETMASK, &sigSet, 0))
        die("Unable to unblock %s from signal mask", sigabbrev_np(aSignal));

    if (-1 == aSigWrFd) {

        kill(selfPid, aSignal);
        die("Unable to kill pid %d using %s", selfPid, sigabbrev_np(aSignal));

    } else {

        DEBUG("Dispatch %s", sigabbrev_np(aSignal));

        dispatch_parent(aSigWrFd, aSignal);

        do
            sigsuspend(&sigSet);
        while (EINTR == errno);

        die("Unable to terminate pid %d using %s",
            selfPid, sigabbrev_np(aSignal));

    }
}

/* -------------------------------------------------------------------------- */
static int
reap_process(int aSigWrFd, pid_t aPid, int aStatus, int aSignal, pid_t aFgPgid)
{
    if (aFgPgid) {
        DEBUG("Restoring foreground pgid %d", aFgPgid);

        /* Be aware that the original process group might no longer be
         * available, Check the common case where the parent is launched
         * from a job control shell.
         */

        if (tcsetpgrp(STDIN_FILENO, aFgPgid))
            if (ESRCH != errno || aFgPgid != getpgrp())
                die("Unable to restore foreground pgid %d", aFgPgid);
    }

    int termSig = aSignal;

    if (!termSig) {
        if (WIFSIGNALED(aStatus))
            termSig = WTERMSIG(aStatus);
    }

    if (termSig) {
        DEBUG("Terminating pid %d with %s", aPid, sigabbrev_np(termSig));
        terminate(aSigWrFd, termSig);
    }

    int exitCode = WEXITSTATUS(aStatus);

    DEBUG("Exiting pid %d with %d", aPid, exitCode);
    return exitCode;
}

/* -------------------------------------------------------------------------- */
static int
handle_signal(int aFd, pid_t aPid, int aTtyFd)
{
    int sigPid = -1;

    struct signalfd_siginfo sigInfo;

    if (sizeof(sigInfo) == read(aFd, &sigInfo, sizeof(sigInfo))) {

        DEBUG("Caught %s code %d",
            sigabbrev_np(sigInfo.ssi_signo), sigInfo.ssi_code);

        /* Caught signals are propagated to the child. No attempt is made
         * to handle the signals locally until waitpid(2) detects that
         * they have caused the child to change state.
         */

        if (SIGCHLD == sigInfo.ssi_signo) {

            sigPid = sigInfo.ssi_pid;

            DEBUG("SIGCHLD pid %d", sigPid);

        } else {

            sigPid = 0;

            int sendSig = 0;

            if (SI_KERNEL == sigInfo.ssi_code) {

                sendSig = sigInfo.ssi_signo;

            } else if (SI_USER == sigInfo.ssi_code) {

                /* To avoid sending the child a signal that it already
                 * knows about, only propagate signals to the child that
                 * were sent by another party.
                 */

                if (sigInfo.ssi_pid != aPid)
                    sendSig = sigInfo.ssi_signo;
            }

            if (sendSig) {

                /* To mimic the shell, job control signals are sent to the
                 * entire child process group, whereas termination signals
                 * are sent to the child process alone and rely on the
                 * fact that the fate of the process hierarchy is tied
                 * to the pid 1 process.
                 */

                switch (sendSig) {
                default:
                    DEBUG("Sending %s to pid %d", sigabbrev_np(sendSig), aPid);

                    if (kill(aPid, sendSig)) {
                        if (ESRCH != errno)
                            die("Unable to propagate %s to pid %d",
                                sigabbrev_np(sendSig), aPid);
                    }
                    break;

                case SIGCONT:
                case SIGTSTP:

                    /* Job control related signals require a propagation
                     * of the foreground process group, along with the
                     * signal itself.
                     */

                    foreground(aTtyFd, aPid);
                    /* Fall through */

                case SIGINT:
                    DEBUG("Sending %s to pgid %d", sigabbrev_np(sendSig), aPid);

                    if (killpg(aPid, sendSig)) {
                        if (ESRCH != errno)
                            die("Unable to propagate %s to pgid %d",
                                sigabbrev_np(sendSig), aPid);
                    }
                    break;
                }
            }
        }
    }

    return sigPid;
}

/* -------------------------------------------------------------------------- */
static int
configure_signal()
{
    static const int handleSignals[] = {
        SIGHUP,
        SIGINT,
        SIGQUIT,
        SIGTERM,
        SIGCHLD,
        SIGTSTP,
        SIGCONT,
    };

    sigset_t sigSet;

    if (sigfillset(&sigSet))
        die("Unable to initialise full signal set");

    if (sigprocmask(SIG_SETMASK, &sigSet, 0))
        die("Unable to block signals for signalfd");

    if (sigemptyset(&sigSet))
        die("Unable to initialise empty signal set");

    for (size_t ix = 0; ix < ARRAYSIZE(handleSignals); ++ix) {

        int signal = handleSignals[ix];
        const char *signalName = sigabbrev_np(signal);

        if (sigaddset(&sigSet, signal))
            die("Unable to add %s to signal set", signalName);
    }

    return signalfd(-1, &sigSet, SFD_CLOEXEC);
}

/* -------------------------------------------------------------------------- */
static int
handle_request(int aFd, int aPid, int aTtyFd)
{
    /* Handle a signal request sent from the child to the parent. Remember
     * that the child runs as pid 1 in the new pid namespace, and so will only
     * receive signals that it is prepared to handle, or signals
     * that cannot be ignored (ie SIGKILL, and SIGSTOP).
     *
     * Signal requests are sent for stopping or terminating, so always
     * choose to send either SIGKILL or SIGSTOP no matter what the
     * requested signal.
     *
     * Note that it is impossible for a stopped child to send a
     * continuation request.
     */

    int req = wait_child(aFd);

    if (-1 != req) {

        int reqSig = req;

        switch (reqSig) {
        default:
            reqSig = SIGKILL;

            DEBUG("Terminating pid %d with %s",
                aPid, sigabbrev_np(reqSig));
            break;

        case SIGTTIN:
        case SIGTTOU:

            if (foreground(aTtyFd, aPid)) {
                reqSig = SIGCONT;

                DEBUG("Resuming pid %d with %s",
                    aPid, sigabbrev_np(reqSig));

                req = 0;
                break;
            }
            /* Fall through */

        case SIGSTOP:
        case SIGTSTP:
            reqSig = SIGSTOP;

            DEBUG("Stopping pid %d with %s",
                aPid, sigabbrev_np(reqSig));

            req = 0;
            break;
        }

        if (kill(aPid, reqSig)) {
            if (ESRCH != errno)
                die("Unable to kill pid %d using %s",
                    aPid, sigabbrev_np(reqSig));
        }

    }

    return req;
}

/* -------------------------------------------------------------------------- */
static int
wait_process(
    int aSigRdFd, int aSigWrFd, pid_t aChildPid, int aTtyFd, pid_t aFgPgid)
{
    int sigFd = configure_signal();
    if (-1 == sigFd)
        die("Unable to create signalfd");

    int waitStatus = 0;
    int termSig = 0;

    struct pollfd pollFds[2] = {
        { .fd = sigFd,    .events = POLL_IN, },
        { .fd = aSigRdFd, .events = POLL_IN, },
    };

    while (1) {

        int numFds = poll(pollFds, ARRAYSIZE(pollFds), -1);
        if (-1 == numFds) {
            if (EINTR != errno)
                die("Unable to poll");
            continue;
        }

        if (pollFds[0].revents & (POLLIN | POLLHUP)) {

            int sigPid = handle_signal(sigFd, aChildPid, aTtyFd);

            if (-1 == sigPid) {

                if (EINTR != errno)
                    die("Unable to handle signal");

            } else if (sigPid) {

                pid_t waitPid = waitpid(
                    sigPid, &waitStatus, WNOHANG | WUNTRACED);

                if (-1 == waitPid) {

                    if (EINTR != errno)
                        die("Unable to wait for children");

                } else if (waitPid) {

                    DEBUG("Wait pid %d status 0x%x", waitPid, waitStatus);

                    if (aChildPid == waitPid) {

                        if (!WIFSTOPPED(waitStatus))
                            break;

                        stop(
                            WSTOPSIG(waitStatus),
                            aSigWrFd, aChildPid, aTtyFd);
                    }
                }
            }
        }

        if (pollFds[1].revents & (POLLIN | POLLHUP)) {

            int sigRequest = handle_request(aSigRdFd, aChildPid, aTtyFd);

            if (-1 == sigRequest) {

                if (errno) {

                    if (EINTR != errno)
                        die("Unable to read signal request");

                } else {

                    DEBUG("Signal request pipe closed");

                    pollFds[1].fd = -1;

                }

            } else if (sigRequest) {

                termSig = sigRequest;

                int waitPid;

                do
                    waitPid = waitpid(aChildPid, &waitStatus, 0);
                while (-1 == waitPid && EINTR == errno);

                if (waitPid != aChildPid)
                    die("Unable to wait for pid %d", aChildPid);

                break;

            }
        }
    }

    if (termSig)
        DEBUG("Reaped pid %d with %s", aChildPid, sigabbrev_np(termSig));

    return reap_process(aSigWrFd, aChildPid, waitStatus, termSig, aFgPgid);
}

/* -------------------------------------------------------------------------- */
static void
drop_stdio(int aTtyFd)
{
    static const char sDevNull[] = "/dev/null";

    int devNullFd = open(sDevNull, O_RDWR);

    if (STDIN_FILENO == aTtyFd || STDOUT_FILENO == aTtyFd)
        die("Unexpected controlling terminal %d", aTtyFd);

    int stdinFd = devNullFd;
    if (-1 != aTtyFd)
        stdinFd = aTtyFd;

    if (-1 == dup2(stdinFd, STDIN_FILENO))
        die("Unable to drop stdin");

    if (-1 == dup2(devNullFd, STDOUT_FILENO))
        die("Unable to drop stdout");

    if (STDIN_FILENO != devNullFd && STDOUT_FILENO != devNullFd)
        close(devNullFd);
}

/* -------------------------------------------------------------------------- */
static void
run_init_pid1(int aChildFd, pid_t aChildPid, int aTtyFd)
{
    pid_t selfPid = getpid();
    pid_t parentPid = getppid();

    if (1 != selfPid)
        die("Child unexpectedly running as pid %d", selfPid);

    if (0 != parentPid)
        die("Parent unexpectedly detected as pid %d", parentPid);

    /* The init pid 1 process is treated specially by the kernel because
     * it is marked with SIGNAL_UNKILLABLE. This causes the kernel to
     * skip delivery of all, except SIGSTOP and SIGKILL that have
     * been generated internally or delivered from an ancestor namespace.
     *
     * In summary:
     *
     *   o SIGKILL and SIGSTOP from any ancestor pid namespace will be delivered
     *   o SIGKILL and SIGSTOP from within the new pid namespace is ignored,
     *     including from the process itself, irrespective of privilege
     *   o SIGTERM, etc, are delivered only if handled
     */

    exit(wait_process(-1, aChildFd, aChildPid, aTtyFd, 0));
}

/* -------------------------------------------------------------------------- */
static void
drop_privileges()
{
    /* Drop privileges, after PDEATHSIG is configured, to avoid
     * taking unintended actions.
     *
     * Drop CAP_SYS_ADMIN capability from the permitted and
     * effective sets. Leave the capability in the other
     * sets, in particular the inheritable set, so that later
     * execve(2) can raise privileges again.
     */

    cap_t capSet = cap_get_proc();
    if (!capSet)
        die("Unable to query process capabilities");

    cap_value_t clearCaps[] = { CAP_SYS_ADMIN };
    cap_flag_t capSets[] = { CAP_EFFECTIVE, CAP_PERMITTED };

    for (unsigned cx = 0; cx < ARRAYSIZE(capSets); ++cx) {
        if (cap_set_flag(
                    capSet, capSets[cx],
                    ARRAYSIZE(clearCaps), clearCaps, CAP_CLEAR))
            die("Unable to clear process CAP_SYS_ADMIN");
    }

    if (cap_set_proc(capSet))
        die("Unable to configure process capabilities");

    for (unsigned cx = 0; cx < ARRAYSIZE(capSets); ++cx) {
        if (cap_set_flag(
                    capSet, capSets[cx],
                    ARRAYSIZE(clearCaps), clearCaps, CAP_SET))
            die("Unable to clear process CAP_SYS_ADMIN");
    }

    errno = 0;
    if (!cap_set_proc(capSet))
        die("Unexpected escalation of process capabilies");

    cap_free(capSet);

    /* Forcing real, effective, and saved uids and gids to match the values
     * of the user invoking the process.
     *
     * This is important to allow an unprivileged kill(2) to deliver a
     * signal to this process running as pid 1.
     *
     * The supplementary group list inherited by the process remains unchanged.
     */

    const gid_t gid = getgid();
    const uid_t uid = getuid();

    if (setresgid(gid, gid, gid))
        die("Unable to set gid");

    if (setresuid(uid, uid, uid))
        die("Unable to set uid");

    uid_t ruid_, * const ruid = &ruid_;
    uid_t euid_, * const euid = &euid_;
    uid_t suid_, * const suid = &suid_;

    if (getresuid(ruid, euid, suid))
        die("Unable to query process uid");

    if (uid != *ruid || uid != *euid || uid != *suid)
        die("Mismatched uid %d ruid %d euid %d suid %d",
            uid, ruid, euid, suid);

    gid_t rgid_, * const rgid = &rgid_;
    gid_t egid_, * const egid = &egid_;
    gid_t sgid_, * const sgid = &sgid_;

    if (getresgid(rgid, egid, sgid))
        die("Unable to query process gid");

    if (gid != *rgid || gid != *egid || gid != *sgid)
        die("Mismatched gid %d rgid %d egid %d sgid %d",
            gid, *rgid, *egid, *sgid);

    gid_t fsgid_ = setfsgid(-1), * const fsgid = &fsgid_;
    uid_t fsuid_ = setfsuid(-1), * const fsuid = &fsuid_;

    if (gid != *fsgid)
        die("Unexpected filesystem gid %d", *fsgid);

    if (uid != *fsuid)
        die("Unexpected filesystem uid %d", fsuid);

    if (uid) {
        errno = 0;
        if (!setreuid(-1, 0) || !setregid(-1, 0) ||
                !setreuid(0, -1) || !setregid(0, -1))
            die("Unexpected privilege escalation");
    }

    errno = 0;
    if (!unshare(CLONE_NEWPID))
        die("Unexpected unshare privilege escalation");

    /* Now that privileges have been dropped, allow user core dumps which
     * have the side-effect of reconfiguring the ownership of /proc/pid.
     */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
        die("Unable to enable core dumps");
}

/* -------------------------------------------------------------------------- */
static void
verify_unprivileged_role()
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    uid_t euid = geteuid();
    gid_t egid = getegid();

    if (uid != euid || gid != egid)
        die("Unexpected effective uid %d gid %d", euid, egid);

    uid_t fsuid = setfsuid(-1);
    gid_t fsgid = setfsgid(-1);

    if (uid != fsuid || gid != fsgid)
        die("Unexpected fsuid %d fsgid %d", fsuid, fsgid);
}

/* -------------------------------------------------------------------------- */
static int
run_parent(struct Tty *aTty, struct Parent *aParent)
{
    /* If there is a pid to match with getppid(2), then tie its fate
     * together with the parent.
     */

    if (-1 != sPPid) {
        DEBUG("Checking parent pid %ld", sPPid);
        pdeathsig(sPPid);
    }

    /* Avoid holding references to stdin and stdout, leaving only
     * the grandchild to hold references.
     */

    int ttyFd = aTty->mFd;

    drop_stdio(ttyFd);

    if (-1 != ttyFd) {
        close(ttyFd);
        ttyFd = STDIN_FILENO;
    }

    /* Ignore SIGPIPE so that write(2) errors will return EPIPE, rather
     * than terminating the caller. Prefer EPIPE since the writing loop
     * already has to handle other kinds of failure, and when invoked
     * from a shell, to avoid showing users confusing "Broken pipe" messages.
     */

    if (SIG_ERR == signal(SIGPIPE, SIG_IGN))
        die("Unable to ignore SIGPIPE");

    /* Do not send a heartbeat to the child until after the child has
     * configured PDEATHSIG. This allows the child to detect the
     * case where the parent terminates prematurely.
     */

    int syncReq;
    while (1) {
        syncReq = wait_child(aParent->mChild.mSyncRd);

        if (-1 != syncReq)
            break;

        if (EINTR != errno) {

            /* If the child terminates prematurely, no data will be read.
             * In this case, pretend that the child actually sent the
             * expected synchronisation value, and fall through to
             * waiting for the child process.
             */

            if (!errno)
                syncReq = 0;

            break;
        }
    }

    if (0 != syncReq)
        die("Unable to synchronise with pid namespace %d", syncReq);

    /* Now that the child has configured PDEATHSIG (or terminated)
     * send a heartbeat to the child to show that the parent has
     * not terminated. This allows the child to detect that the
     * parent termination did not race it configuring PDEATHSIG.
     *
     * If the child itself terminated prematurely, fall through
     * to wait for the termination status.
     */

    foreground(ttyFd, aParent->mChild.mPid);

    dispatch_child(aParent->mChild.mSyncWr);
    close(aParent->mChild.mSyncWr);

    return wait_process(
        aParent->mChild.mSyncRd, -1, aParent->mChild.mPid, ttyFd, aTty->mPgid);
}

/* -------------------------------------------------------------------------- */
static void
run_child(struct Tty *aTty, struct Child *aChild)
{
    /* Security modules will reset PDEATHSIG when privileges
     * change, so delay configuring PDEATHSIG until after uid and
     * gid are modified.
     *
     * When configuring PDDEATHSIG, getppid(2) does not convey
     * any useful information because it always returns zero
     * reflecting the fact that the parent lives in a different
     * pid namespace.
     *
     * Instead signal via mParent.mSyncWr to trigger the parent to
     * send a heartbeat back to the child.
     */

    pdeathsig(0);

    dispatch_parent(aChild->mParent.mSyncWr, 0);

    /* Read the heartbeat from the parent. Lack of a heartbeat means
     * that the parent terminated just before PDEATHSIG was configured.
     */

    if (wait_parent(aChild->mParent.mSyncRd))
        pdeathsig(-1);

    close(aChild->mParent.mSyncRd);

    int grandChildSync[2];
    if (pipe2(grandChildSync, O_CLOEXEC))
        die("Unable to create grandchild sync pipe");

    int grandChildSidSync[2];
    if (pipe2(grandChildSidSync, O_CLOEXEC))
        die("Unable to create grandchild sid sync pipe");

    /* Not all commands are capable of running as pid 1, because they
     * get confused by seeing adopted child processes they did
     * not fork. For this reason, fork a grandchild to execute the command.
     */

    pid_t childPid = getpid();

    pid_t grandChildPid = fork();
    if (-1 == grandChildPid)
        die("Unable to fork grandchild");

    /* The child runs as the pid 1 root process in the new pid namespace,
     * leaving the grandchild to execute the command.
     */

    if (grandChildPid) {

        /* The child was configured as process group leader above, and
         * the parent, child, and grandchild, all belong to the same
         * session with the same controlling terminal.
         *
         * Importantly, the child and grandchild have non-zero pgid
         * in the new pid namespace.
         *
         * Force the grandchild to be a process group leader to ensure
         * that it can be controlled as a separate foreground process group.
         * If the parent was a session leader, ensure that the grandchild is
         * also a session leader and that getsid(2) will report a non-zero
         * value.
         *
         * This has the consequence that neither the child, nor the
         * grandchild, can later be made session leaders since setsid(2)
         * requires that the caller cannot be a process group leader.
         *
         * It is important that process groups of both the child and
         * grandchild are not orphaned otherwise job control
         * signals SIGTSTP, SIGTTOU, and SIGTTIN, will be ignored.
         *
         * Posix says:
         *
         *     A process that is a member of an orphaned process group
         *     shall not be allowed to stop in response to the SIGTSTP,
         *     SIGTTIN, or SIGTTOU signals. In cases where delivery of
         *     one of these signals would stop such a process, the signal
         *     shall be discarded.
         */

        close(grandChildSidSync[1]);
        if (aChild->mParent.mSid == aChild->mParent.mPgid) {

            wait_child(grandChildSidSync[0]);

        } else {

            if (setpgid(grandChildPid, grandChildPid))
                die("Unable to configure pgid %d", grandChildPid);

        }
        close(grandChildSidSync[0]);

        /* Avoid holding references to stdin and stdout, leaving only
         * the grandchild to hold references.
         *
         * Note also that the process might have a controlling terminal, but
         * have might also have been started as a background task. If
         * running as a foreground task, set the grandchild as the foreground
         * process group.
         */

        int ttyFd = aTty->mFd;

        drop_stdio(ttyFd);

        if (-1 != ttyFd) {
            close(ttyFd);
            ttyFd = STDIN_FILENO;
        }

        foreground(ttyFd, grandChildPid);

        close(grandChildSync[0]);
        dispatch_child(grandChildSync[1]);
        close(grandChildSync[1]);

        run_init_pid1(aChild->mParent.mSyncWr, grandChildPid, ttyFd);
    }

    /* If the parent was placed in its own session, place the grandchild
     * in its own session to ensure that getsid(2) returns a non-zero
     * value in the new pid namespace.
     */

    close(grandChildSidSync[0]);
    if (aChild->mParent.mSid == aChild->mParent.mPgid) {
        if (-1 == setsid())
            die("Unable to create new session sid %d", getpid());
        dispatch_parent(grandChildSidSync[1], 0);
    }
    close(grandChildSidSync[1]);

    close(aTty->mFd);

    close(aChild->mParent.mSyncWr);

    /* The child, and grandchild run in the same pid namespace, so the
     * outcome from getppid(2) is meaningful when configuring PDEATHSIG.
     */

    pdeathsig(childPid);

    close(grandChildSync[1]);
    if (wait_parent(grandChildSync[0]))
        pdeathsig(-1);
    close(grandChildSync[0]);

    if (sigprocmask(SIG_SETMASK, &aChild->mInheritedSet, 0))
        die("Unable to restore inherited signal mask");

    DEBUG("Execute %s", *aChild->mCmd);

    execvp(*aChild->mCmd, aChild->mCmd);

    die("Unable to execute %s", *aChild->mCmd);
}

/* -------------------------------------------------------------------------- */
int
main(int argc, char **argv)
{
    /* PRIVILEGED */ struct Service service;
    /* PRIVILEGED */
    /* PRIVILEGED */ pid_t childPid = privileged(&service, argc, argv);
    /* PRIVILEGED */
    /* PRIVILEGED */ drop_privileges();

    /* All the code beyond thing point runs at reduced privilege.
     * Explicitly verify that the process is not running with
     * elevated privileges.
     */

    verify_unprivileged_role();

    /* The child process is runs in the new pid nammespace, and will
     * follow up to run the target command. The parent waits for the
     * child to terminate, and also handles requests from the child
     * to send a termination signal.
     */

    if (!childPid)
        run_child(&service.mTty, &service.mChild);

    return run_parent(&service.mTty, &service.mParent);
}

/* -------------------------------------------------------------------------- */
