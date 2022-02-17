#!/usr/bin/env bash
# -*- sh-basic-offset:4; indent-tabs-mode:nil -*- vi: set sw=4 et:

[ -z "${0##/*}" ] || exec "$PWD/$0" "$@"

set -eu

say()
{
    printf '%s\n' "$*"
}

usage()
{
    {
        say "usage: ${0##*/} [--verbose] [--no-root] pidspace"
        say "options:"
        say "  --verbose  Print output even if test succeeds"
        say "  --no-root  Do not use sudo to test as root"
        say "arguments:"
        say "  pidspace   Path to executable to test"
    } >&2
}

expect()
{
    test "$@" || {
        say "Failed at line ${BASH_LINENO[0]}: $*" >&2
        exit 1
    }
}

ps_pidspace()
{
    [ $# -ne 0 ] || set -- -U "$UID"
    ps -o ppid=,pid=,pgid=,sid=,stat=,tpgid=,uid=,args= "$@" | grep -v grep
}

exec_pidspace()
{
    local CMD=$PIDSPACE
    local EXEC=

    while [ $# -ge 1 ] ; do
        if [ x"$1" = x"--no-setsid" ] ; then
            shift
        elif [ x"$1" = x"--setsid" ] ; then
            EXEC='setsid --wait'
            shift
        elif [ x"$1" = x"--chain" ] ; then
            EXEC=$2
            shift 2
        elif [ x"$1" = x"--cmd" ] ; then
            CMD=$2
            shift 2
        else
            break
        fi
    done

    exec $EXEC "$CMD" --debug "$@"
}

test_pidspace_hierarchy()
{
    # PPID PID  PGID SID TTY   TPGID STAT UID  TIME COMMAND
    # 0    1    1    0   pts/1 0     S    1000 0:00 pidspace -- ps wwwaxjf
    # 1    2    2    0   pts/1 0     R    1000 0:00 ps wwwaxjf

    local PS
    PS=$(exec_pidspace -- ps -o ppid=,pid=,pgid=,sid=,tty=,tpgid=,uid=)
    expect 2 = "$(say "$PS" | wc -l)"
    expect 2 = "$(say "$PS" | awk -v UID="$UID" '$NF == UID' | wc -l)"
    expect 1 = "$(say "$PS" | awk '$1 == 0 && $2 == 1' | wc -l)"
    expect 1 = "$(say "$PS" | awk '$1 == 1 && $2 > 1' | wc -l)"
    expect 2 = "$(say "$PS" | awk '$2 == $3' | wc -l)"
    expect 2 = "$(say "$PS" | awk '$4 <= 0' | wc -l)"
    expect 2 = "$(say "$PS" | awk '$6 <= 0 || $6 == 2' | wc -l)"
}

test_pidspace_devnull()
{
    local EXEC=$1 ; shift

    # PPID PID  PGID SID TTY    TPGID STAT UID  TIME COMMAND
    # 123  405  345  234 pts/1  234   S    0    0:00 pidspace sleep 59

    (
      exec </dev/random
      exec >/dev/random 2>&1
      exec_pidspace "$EXEC" -- sh -c "exec sleep 59 || :"
    ) &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done
    local CHILD
    CHILD=$(ps_pidspace | awk '/ 59$/ {print $1}')

    local PS
    PS=$(ps_pidspace -p $!)

    local PARENTFDS
    PARENTFDS=$(ls -l /proc/$!/fd | tail -n +2)

    local CHILDFDS
    CHILDFDS=$(ls -l /proc/$CHILD/fd | tail -n +2)

    local GRANDCHILDFDS
    GRANDCHILDFDS=$(ls -l /proc/$GRANDCHILD/fd | tail -n +2)

    kill $! || :
    wait $! || :

    expect 1 = "$(say "$PS" | wc -l)"
    if [ x"$EXEC" = x"--setsid" ] ; then
        expect 1 = "$(say "$PS" | awk '$2 == $3' | wc -l)"
    else
        expect 1 = "$(say "$PS" | awk '$2 != $3' | wc -l)"
    fi
    expect 1 = "$(say "$PS" | awk -v UID="$UID" '$7 == UID' | wc -l)"

    expect 1 = "$(say "$PARENTFDS" | awk '/ 0 -> .dev.(null|tty)$/' | wc -l)"
    expect 1 = "$(say "$PARENTFDS" | awk '/ 1 -> .dev.null$/' | wc -l)"
    expect 1 = "$(say "$PARENTFDS" | awk '/ 2 -> .dev.random$/' | wc -l)"
    expect 1 = "$(say "$PARENTFDS" | awk '/ -> .*pipe:/' | wc -l)"
    expect 1 = "$(say "$PARENTFDS" | awk '/ -> .*[[]signalfd[]]/' | wc -l)"
    expect 5 = "$(say "$PARENTFDS" | wc -l)"

    expect 1 = "$(say "$CHILDFDS" | awk '/ 0 -> .dev.(null|tty)$/' | wc -l)"
    expect 1 = "$(say "$CHILDFDS" | awk '/ 1 -> .dev.null$/' | wc -l)"
    expect 1 = "$(say "$CHILDFDS" | awk '/ 2 -> .dev.random$/' | wc -l)"
    expect 1 = "$(say "$CHILDFDS" | awk '/ -> .*pipe:/' | wc -l)"
    expect 1 = "$(say "$CHILDFDS" | awk '/ -> .*[[]signalfd[]]/' | wc -l)"
    expect 5 = "$(say "$CHILDFDS" | wc -l)"

    expect 3 = "$(say "$GRANDCHILDFDS" | awk '/ -> .dev.random$/' | wc -l)"
    expect 3 = "$(say "$GRANDCHILDFDS" | wc -l)"
}

test_pidspace_securefds()
{
    (
      exec <&- >&- 2>&-
      exec_pidspace --chain sudo -- sh -c "exec sleep 59 || :"
    ) &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace -U 0 | awk '/ 59$/ {print $2}')
    done

    local GRANDCHILDFDS
    GRANDCHILDFDS=$(sudo ls -l /proc/$GRANDCHILD/fd | tail -n +2)

    sudo kill "$GRANDCHILD" || :
    wait $! || :

    expect 1 = "$(say "$GRANDCHILDFDS" | awk '/ 0 -> .dev.full$/' | wc -l)"
    expect 1 = "$(say "$GRANDCHILDFDS" | awk '/ 1 -> .dev.null$/' | wc -l)"
    expect 1 = "$(say "$GRANDCHILDFDS" | awk '/ 2 -> .dev.null$/' | wc -l)"
    expect 3 = "$(say "$GRANDCHILDFDS" | wc -l)"
}

test_pidspace_sys_admin()
{
    (
      local CHAIN="--"
      CHAIN="--reuid $(id -u) --regid $(id -g) --init-groups $CHAIN"
      CHAIN="--ambient-caps +sys_admin --inh +sys_admin $CHAIN"
      CHAIN="sudo setpriv $CHAIN"

      set -- sh -c "exec sleep 59 || :"
      exec_pidspace --cmd ./pidspace --chain "$CHAIN" -- "$@"
    ) &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done

    local PRIVILEGES
    PRIVILEGES=$(cat /proc/$GRANDCHILD/status | grep '^Cap')

    sudo kill "$GRANDCHILD" || :
    wait $! || :

    expect -n "$(
        say "$PRIVILEGES" | awk '$1 == "CapEff:" && $2 ~ /^00*$/')"
    expect -n "$(
        say "$PRIVILEGES" | awk '$1 == "CapPrm:" && $2 ~ /^00*$/')"
}

test_pidspace_orphan_children_early()
{
    (
      # Verify that a zombie inherited across an execve(2) will
      # not be confusing, and will be reaped.

      ( true ) > /dev/null 2>&1 &
      exec_pidspace -- sh -c "exec sleep 59 || :"
    ) &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done

    local CHILDREN
    CHILDREN=$(ps_pidspace --ppid $!)
    expect 1 = "$(say "$CHILDREN" | wc -l)"

    kill $! || :
    wait $! || :
}

test_pidspace_orphan_children_late()
{
    local JITTER
    JITTER=$(printf 0.00%03d $(( $RANDOM % 1000 )) )
    (
      # Verify that a child inherited across an execve(2) will
      # not be confusing, and will be reaped when it terminates.

      ( sleep $JITTER ) > /dev/null 2>&1 &
      exec_pidspace -- sh -c "exec sleep 59 || :"
    ) &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done

    sleep $JITTER
    sleep $JITTER

    local CHILDREN
    while : ; do
        CHILDREN=$(ps_pidspace --ppid $!)
        [ -z "${CHILDREN##*<defunct>*}" ] || break
    done
    expect 1 = "$(say "$CHILDREN" | wc -l)"

    kill $! || :
    wait $! || :
}

test_pidspace_true()
{
    ( exec_pidspace -- sh -c 'exec true ; sleep 59') &
    local RC=0
    wait $! || RC=$?
    expect 0 = "$RC"
}

test_pidspace_false()
{
    ( exec_pidspace -- sh -c 'exit 42 ; sleep 59') &
    local RC=0
    wait $! || RC=$?
    expect 42 = "$RC"
}

test_pidspace_parented()
{
    local PARENT=$BASHPID

    ( exec_pidspace --ppid "$PARENT" -- sh -c 'exec true ; sleep 59') &
    local RC=0
    wait $! || RC=$?
    expect 0 = "$RC"
}

test_pidspace_orphaned()
{
    ( exec_pidspace --ppid 1 -- sh -c 'exec true ; sleep 59') &
    local RC=0
    wait $! || RC=$?
    expect 137 = "$RC"
}

test_pidspace_kill_grandchild()
{
    local SIGNAL=$1 ; shift
    local EXEC=$1 ; shift

    ( exec_pidspace -- sh -c "$EXEC sleep 59 || exit \$?") &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done
    kill -"$SIGNAL" "$GRANDCHILD"
    local RC=0
    wait $! || RC=$?
    expect $((128 + $(kill -l "$SIGNAL") )) = "$RC"
}

test_pidspace_kill_child()
{
    local SIGNAL=$1 ; shift
    local EXEC=$1 ; shift

    ( exec_pidspace -- sh -c "$EXEC sleep 59 || :") &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done
    local CHILD
    CHILD=$(ps_pidspace | awk '/ 59$/ {print $1}')
    kill -"$SIGNAL" "$CHILD"
    local RC=0
    wait $! || RC=$?
    expect $((128 + $(kill -l "$SIGNAL") )) = "$RC"
}

test_pidspace_kill_parent()
{
    local SIGNAL=$1 ; shift
    local EXEC=$1 ; shift

    ( exec_pidspace -- sh -c "$EXEC sleep 59 || :") &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done
    ps wwwaxjf >&2
    kill -"$SIGNAL" "$!"
    local RC=0
    wait $! || RC=$?
    expect $((128 + $(kill -l "$SIGNAL") )) = "$RC"
}

test_pidspace_job()
{
    local EXEC=$1 ; shift

    ( exec_pidspace -- sh -c "
        trap 'exit 42' CONT ; ( $EXEC sleep 59 )  & wait \$! || :") &
    local GRANDCHILD=
    while [ -z "$GRANDCHILD" ] ; do
        GRANDCHILD=$(ps_pidspace | awk '/ 59$/ {print $2}')
    done
    kill -TSTP "$!"
    expect T = "$(ps_pidspace | awk '/ 59$/ {print substr($5,1,1)}')"
    kill -CONT "$!"
    local RC=0
    wait $! || RC=$?
    expect 42 = "$RC"
}

cleanup()
{
    local JOB
    for JOB in $(jobs -p) ; do
        set -- $(ps -o uid= "$JOB")
        if [ $# -ne 0 ] && [ x"$1" = x"0" ] ; then
            set -- sudo
        else
            set --
        fi
        set -- "$@" kill -KILL $(ps -o pid= --pid "$JOB" --ppid "$JOB")
        [ x"${@: -1}" = x"-KILL" ] || "$@" || :
    done
}

run()
{
    local OUTPUT
    OUTPUT=$(
        trap cleanup EXIT
        exec 2>&1 >/dev/null
        set -x
        ps wwwaxjf >&2
        ps -o pgid=,tpgid= -p $$ >&2
        expect -z "$(ps_pidspace | grep 'pidspace ')"
        "$@"
        expect -z "$(ps_pidspace | grep 'pidspace ')"
    ) || {
        say "$OUTPUT"
        say "FAILED -$- $*"
        false
    }
    [ -z "${OPT_VERBOSE++}" ] ||
        say "$OUTPUT"
    say "OK     -$- $*"

    # Reset the controlling terminal by running a command with job
    # control enabled. Enable job control temporarily if required.

    if [ -z "${-##*m*}" ] ; then
        command sleep 0
    else
        set -m
        command sleep 0
        set +m
    fi
}

run_tests()
{
    local PIDSPACE=$1 ; shift

    run test_pidspace_true
    run test_pidspace_false

    run test_pidspace_parented
    run test_pidspace_orphaned

    run test_pidspace_hierarchy
    run test_pidspace_devnull --no-setsid
    run test_pidspace_devnull --setsid

    [ -n "${OPT_NO_ROOT++}" ] || {
      run test_pidspace_securefds
      run test_pidspace_sys_admin
    }

    run test_pidspace_orphan_children_early
    run test_pidspace_orphan_children_late

    local EXEC
    local SIGNAL
    for EXEC in ': ;' 'exec' ; do
        for SIGNAL in SIGHUP SIGTERM SIGKILL SIGINT SIGQUIT ; do

            run test_pidspace_kill_grandchild "$SIGNAL" "$EXEC"

            case "$SIGNAL $EXEC" in
            "SIGINT : ;" | "SIGQUIT : ;")
                ;;
            *)
                run test_pidspace_kill_child "$SIGNAL" "$EXEC"
                ;;
            esac

            run test_pidspace_kill_parent "$SIGNAL" "$EXEC"

            case "$EXEC" in
            exec)
                ;;
            *)
                # Do not run the test if job control is enabled, because
                # subshells in $(...) will ignore SIGTSTP.

                [ -z "${-##*m*}" ] ||
                    run test_pidspace_job "$EXEC"
                ;;
            esac
        done

    done
}

main()
{
    local OPT_VERBOSE
    [ $# -lt 1 ] || [ x"$1" != x"--verbose" ] || { OPT_VERBOSE= ; shift ; }

    local OPT_NO_ROOT
    [ $# -lt 1 ] || [ x"$1" != x"--no-root" ] || { OPT_NO_ROOT= ; shift ; }

    [ $# -eq 1 ] || usage

    local PIDSPACE=$1 ; shift

    expect -x "$PIDSPACE"

    set -m
    run_tests "$PIDSPACE"

    set +m
    run_tests "$PIDSPACE"
}

main "$@"
