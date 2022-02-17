pidspace
========

Run command in new pid namespace.

#### Background

This utility is useful to house a process tree in a new pid namespace,
so that the fate of all the processes in the tree is tied to the
process at the root of the tree. This simplifies cleaning up of
supervised processes, and avoids the scenario where stragglers run
indefinitely after being adopted by a new parent.

#### Dependencies

* GNU Make
* GNU Automake
* GNU C
* GNU C++ for tests

#### Build

* Run `autogen.sh`
* Configure using `configure`
* Build binaries using `make`
* Run tests using `make check`

#### Usage

```
usage: pidspace [--] cmd ...

arguments:
  cmd     Command to execute
```

#### Examples

```
% pidspace -- s6-svcscan ~/services
```

#### Motivation

Simple services comprise a single process, but more complex
services are implemented with a tree of processes. Supervised
services (eg s6, runit, etc) typically include at least one
separate process which is responsible for curating a rotated
service logs.

When the service terminates, its component processes sometimes
outlive their parents, and escape the process hierarchy to
be adopted by init(1). In some scenarios it is beneficial
to ensure that these processes remain contained in the
service process hierarchy, and that their lifetimes are
tied to the root service process.

Declaring the root service process as a CHILD\_SUBREAPER would
prevent processes from leaving the service process hierarchy.
Encapsulation is incomplete because service processes can outlive
the subreaper and subsequently processes move outside the hierarchy
when it is necessary to adopt orphans.

Using a pid namespace allows the service process hierarchy to
use the root serice process as an independent subreaper, and
uses the lifetime of the root service process to bound the
lifetimes of all processes in the hierarchy.

This can be achieved using `unshare(1)` to unshare the pid namespace,
but unprivileged users are also required to unshare the user namespace
making it difficult to work with an inherited the root filesystem.

Another possibility is to use `bubblewrap(1)` which, as a setuid
program, makes it easy to inherit the root filesystem. Unfortunately,
the use of `PR_SET_NO_NEW_PRIVS` means that processes in the new
pid namespace cannot execute setuid programs. In particular, processes
cannot use `bubblewrap(1)` itself.

The `pidspace` command is setuid to allow it to create a new pid
namespace while still sharing the user namespace, and its narrow
focus on `CLONE_NEWNS` and `CLONE_NEWPID` avoids having to
set `PR_SET_NO_NEW_PRIVS`.

Finally, `pidspace` avoids having to use `chroot(2)` to pivot to
a new root filesystem by only re-mounting `/proc`. This is
sufficient to show processes in the new pid namespace
the correctly matching pids.
