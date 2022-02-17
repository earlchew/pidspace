crontime
========

Compute matching event times in the local timezone for crontab schedules.

#### Background

Crontab schedules are an established way to describe schedules
for recurring activities. The crontime program computes the
next matching event time in the local timezone for a crontab schedule,
taking into account daylight savings changes.

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
usage: crontime [ options ] time [ schedule ] [ < schedule ]

options:
  -j,--jitter N   Jitter the schedule by N seconds [default: 300]

arguments:
  time       Time specific as Unix epoch (eg 1636919408)
  schedule   Schedule using crontab(5) expression (eg * * * * *)
```

#### Examples

```
% export TZ=US/Pacific
% NOW=949181283
% date -d @$NOW
Sat Jan 29 13:28:03 PST 2000
% SCHEDULED=$(crontime 949181283 '*/5 * * * *')
% date -d @$SCHEDULED
Sat Jan 29 13:30:00 PST 2000
```

```
% export TZ=US/Pacific
% NOW=949181283
% date -d @$NOW
Sat Jan 29 13:28:03 PST 2000
% SCHEDULED=$(crontime 949181283 '43 6-9 15-20 5,6 *')
% date -d @$SCHEDULED
Mon May 15 06:43:00 PDT 2000
```

#### Jitter

Unless overridden by the `--jitter 0` option, a small amount of jitter
is added to each scheduled time to counter the tendency to synchronise
events to the start of each minute, or hour.

If the event is scheduled far enough into the future, the jitter will
be symmetric around the scheduled time. Otherwise, the jitter will
be one-sided and will delay the event by a random time.

#### Daylight Savings

Local timezones typically to contend with discontinuities due to daylight
savings adjustments. The disconinuities interact with crontab schedules,
resulting in outcomes that are sometimes unexpected.

#### Beginning Daylight Savings

Typically during spring, a daylight savings change will advance the local
clock and cause the apparent time to skip ahead. For example, in the
US/Pacific timezone, the clock will instantaneously advance from 02:00
to 03:00, as illustrated in the following table:

```
UTC    08  09  10  11  12  13
Local  00  01 [02]
               03  04  05  06

[02]  Hour that is skipped but that will match a schedule
```

To avoid the surprise of a missing event scheduled at the skipped hour,
(eg `30 2 * * *`), or a periodic event during the skipped hour
(eg `30 * * * *`) , the computed schedule will first try to match the
schedule with the skipped hour (as indicated by `[02]`), and then try to
match the new daylight savings time (as indicated by `03`).

This accommodation for the daylight savings change only applies for
the transition period (ie `[02]`, `03`), and once past the scheduler
reverts to the standard behaviour (ie UTC `11`).

The following table shows some examples:

```
30 2   * * *  UTC 1030
30 2,3 * * *  UTC 1030
30 3   * * *  UTC 1030
30 0-4 * * *  UTC 0830, UTC 0930, UTC 1030, UTC 1130
```

#### Ending Daylight Savings

Typically during autumn, a daylight savings change will rewind the local
clock and cause the apparent time to repeat. For example, in the
US/Pacific timezone, the clock will instantaneously rewind from 02:00
to 01:00, as illustrated in the following table:

```
UTC    07  08  09  10  11  12
Local  00  01 -02-
              (01) 02  03  04

-02-  Hour that will not match any schedule
(01)  Hour that will only match a wildcard
```

To avoid the surprise of a duplicate event scheduled during the repeated hour
(eg `30 1 * * *`), the computed schedule will not match the specific
repeated hour (as indicated by `(01)`) during the daylight savings change.

To avoid the complementary surprise of a missing periodic event during
the repeated hour (eg `30 * * * *`), schedules using a wildcard `*` will
match the specific repeated hour (as indicated by `(01)`).

This accommodation for the daylight savings change only applies for
the transition period (ie `(01)`), and once past the scheduler
reverts to the standard behaviour (ie UTC `10`).

The following table shows some examples:

```
30 1   * * *  UTC 0830
30 1,2 * * *  UTC 0830, UTC 1030
30 2   * * *  UTC 1030
30 0-3 * * *  UTC 0730, UTC 0830, UTC 1030, UTC 1130
```
