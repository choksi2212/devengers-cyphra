"""Process collector — the running process table, diffed into OCSF Process Activity.

Sysmon event 1 is the right way to get process telemetry, and on a host where Sysmon
is installed this collector is redundant for launches. It exists because on most
hosts Sysmon is *not* installed, and a SOC with no process visibility at all cannot
answer the first question every investigation asks: what ran, under whose account,
started by what.

**This collector polls, and polling has a blind window.** A process that starts and
exits between two cycles is never seen. That is not an implementation weakness to be
tuned away — it is what polling is, and the processes it misses are exactly the ones
that matter, because ``cmd /c whoami`` lives for eleven milliseconds. Three
consequences are built into the code rather than left to the reader:

* :attr:`ProcessCollector.blind_window_seconds` is published in ``stats_extra`` so
  the number is on the health board next to the event count, not buried here.
* :data:`AUDIT_4688_SETUP` is offered by :meth:`probe` even when the collector is
  perfectly available, because "available" and "complete" are different claims and
  conflating them is how a gap becomes invisible.
* Terminations are emitted from the diff, so a process seen once and gone by the
  next cycle still produces a launch *and* a terminate with a measured lifetime —
  the short-lived processes that are caught are not silently truncated.

**The scan must be fast or the blind window is a lie.** The first version of this
collector read all twelve psutil fields for all ~390 processes every cycle, which
measured at 3.8 seconds. Because :meth:`Collector.run` sleeps the cadence *after* the
cycle returns, a collector configured for a 2 s cadence was blind for 5.8 s at a
stretch while reporting 2.0 — and a ``python -c "time.sleep(3)"`` started between two
polls produced no launch event and no terminate at all, because the scan outlived the
process. It is two passes now: identity only over everything (1 ms), then the
expensive read for new PIDs alone. Steady state went 3.8 s → 1 ms, and
:attr:`ProcessCollector.blind_window_seconds` times the poll instead of assuming it.

**Identity is ``(pid, create_time)``, never ``pid``.** Windows recycles PIDs from a
small space and does it quickly; a busy host can reuse a PID within seconds. Keyed on
PID alone, a recycled PID makes the diff report no change — so the exit of the first
process and the launch of the second both vanish, and the SOC's process table shows
one long-lived process that is actually two, the second of which may be the intrusion.
psutil exposes the same pair as its own identity for the same reason.

**Parent resolution survives the parent's death.** By the time a child is observed,
its parent has frequently exited — that is normal for a launcher, and it is
*characteristic* of process injection and of scripts that spawn and detach. Resolving
the parent only against the live table would leave ``actor_process_name`` empty on
precisely those events. The previous snapshot is kept for one extra cycle and
consulted, so an orphan still names its parent. Where the resolved parent's own
creation time is *later* than the child's, the PID has been recycled and the parent is
reported as unknown with the reason attached, rather than naming the wrong process —
an attacker's parent-PID spoofing (T1134.004) and an ordinary PID recycle look
identical from here, and inventing an answer would corrupt every process tree built
downstream.
"""

from __future__ import annotations

from typing import Any

from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import (
    Availability,
    PullCollector,
    available,
    is_admin,
    is_windows,
    unavailable,
)

#: Offered by :meth:`ProcessCollector.probe` as a *completeness* note even when the
#: collector runs fine. Windows can log process creation itself, as Security event
#: 4688, from the kernel — so it catches the short-lived processes polling cannot.
#: It is off by default on every Windows install, and turning it on is two commands.
#: With ``ProcessCreationIncludeCmdLine`` the command line is included, without which
#: 4688 says a process ran but not what it was told to do, which for
#: ``powershell.exe`` is the whole content of the event.
AUDIT_4688_SETUP = (
    "process telemetry here is polled, so a process that starts and exits between "
    "cycles is not seen. Two ways to close that, both better than a shorter "
    "cadence:\n"
    "    1. Install Sysmon (see the sysmon collector's setup note) — event 1 is "
    "kernel-sourced, carries hashes and parent command line, and misses nothing.\n"
    "    2. Or turn on Windows' own process auditing, from an elevated shell:\n"
    '         auditpol /set /subcategory:"Process Creation" /success:enable\n'
    "         reg add "
    '"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" '
    "/v ProcessCreationIncludeCmdLine /t REG_DWORD /d 1 /f\n"
    "       That produces Security event 4688 with the command line, which the "
    "windows_eventlog collector already maps. Without the second command 4688 says "
    "that something ran but not what it was told to do.\n"
    "  Neither is required for this collector to work. Both change what it can see."
)

#: Executables whose hash is not worth computing: the hash of a 900 MB VM disk image
#: masquerading as an executable costs seconds of I/O and joins against nothing.
#: Chosen well above any real binary (Chrome's largest DLL is ~180 MB).
MAX_HASH_BYTES = 256 * 1024 * 1024

#: How many ``(path, size, mtime)`` keys to remember hashes for. Bounded because the
#: alternative on a build host is a dictionary that grows for as long as the process
#: runs. 4096 covers every distinct binary on a normal host several times over.
HASH_CACHE_SIZE = 4096

#: Fields that describe *what a process is*. Read once, when the process is first
#: seen, and then carried in :attr:`ProcessCollector._seen` for as long as it lives.
#:
#: They are cheap — measured on this host, all seven cost about 75 ms across ~390
#: processes — and they are also immutable for the life of the process, so re-reading
#: them every cycle would spend time to obtain the answer already held. Reading them
#: at first sight has a second benefit that matters more than the time: a process that
#: later drops privileges, is protected, or exits keeps the attribution captured when
#: it launched, instead of degrading to a bare PID at exactly the moment an
#: investigation needs the command line.
_IDENTITY_FIELDS = (
    "pid",
    "ppid",
    "name",
    "exe",
    "cmdline",
    "username",
    "create_time",
    "cwd",
)

#: Fields that change while a process runs — and, measured on this host, the fields
#: that account for essentially the whole cost of scanning the process table:
#:
#:     status       1651 ms      num_threads  1629 ms
#:     cpu_times     733 ms      memory_info   734 ms
#:
#: against 0.9 ms for ``create_time`` and 1.0 ms for ``exe``, over the same ~390
#: processes. The ratio is not a rounding difference; on Windows these four come from
#: a different and far more expensive path than the identifying fields do.
#:
#: This collector therefore does **not** refresh them every cycle by default. That is
#: a deliberate trade with a visible cost, not an optimisation: it means the resource
#: figures on a termination event are the ones read when the process launched, so
#: :meth:`ProcessCollector._terminate` omits lifetime CPU entirely and says why rather
#: than publishing the ~0 that stale counters would produce. Pass
#: ``track_resource_usage=True`` to pay the ~4.4 s per cycle and get the real number.
_VOLATILE_FIELDS = (
    "num_threads",
    "cpu_times",
    "memory_info",
    "status",
)

#: What the first sighting of a process reads: everything.
_FIELDS = _IDENTITY_FIELDS + _VOLATILE_FIELDS


class ProcessCollector(PullCollector):
    """The live process table, diffed on a cadence into launch/terminate events."""

    name = "process"
    cadence_seconds = 2.0
    critical = True
    description = (
        "Process launches and terminations from the live process table, with "
        "parent resolution across the parent's death and hashes of new executables. "
        "Identity-only scan each cycle; full attribution read once, at first sight"
    )

    def __init__(
        self,
        pipeline: Any,
        *,
        hash_executables: bool = True,
        emit_baseline: bool = True,
        track_resource_usage: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(pipeline, **kwargs)
        self.hash_executables = hash_executables
        self.emit_baseline = emit_baseline
        #: Re-read CPU/memory/threads/status every cycle. Off by default because it
        #: costs ~4.4 s per cycle on a 400-process host — see :data:`_VOLATILE_FIELDS`
        #: — and that cost is added directly to the blind window.
        self.track_resource_usage = track_resource_usage

        #: ``(pid, create_time) -> record`` for the processes seen last cycle.
        self._seen: dict[tuple[int, float], dict[str, Any]] = {}
        #: Processes that vanished last cycle, kept one extra cycle so a child whose
        #: parent has already exited can still name it.
        self._recent_dead: dict[int, dict[str, Any]] = {}
        self._first_poll = True
        self._last_poll_at = 0.0
        #: How long the last poll took, and the worst seen. Measured rather than
        #: assumed, because the scan duration *is* part of the blind window and the
        #: first version of this collector was wrong about it by a factor of three.
        self._poll_seconds = 0.0
        self._poll_seconds_worst = 0.0
        #: The first poll's duration, kept apart from the worst case above because it
        #: is a startup cost (full read plus hashing every executable) and not a
        #: recurring one.
        self._first_poll_seconds = 0.0
        #: Boot time, resolved once on demand. ``None`` means not yet asked.
        self._boot_time_cache: float | None = None

        #: ``(path, size, mtime) -> {"sha256": …}``, bounded, insertion-ordered so
        #: the oldest entry is the one evicted.
        self._hash_cache: dict[tuple[str, int, float], dict[str, str]] = {}

        # Counters that make this collector's own blindness measurable rather than
        # assumed. Every one of them is reported in stats_extra.
        self.launches = 0
        self.terminations = 0
        self.baseline_emitted = 0
        self.access_denied = 0
        self.vanished_mid_read = 0
        self.parent_unresolved = 0
        self.parent_pid_recycled = 0
        self.hashes_computed = 0
        self.hashes_from_cache = 0
        self.hash_skipped_too_big = 0
        self.hash_failed = 0

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        """psutil is a hard dependency, so this almost always succeeds.

        The interesting part is the second half: when it *is* available, the reason
        string still carries what this collector cannot see and how to fix it. A
        collector that reports "available" and stops has told the operator that
        process coverage is handled, which for a polled collector is not true.
        """
        try:
            import psutil
        except Exception as exc:
            return unavailable(
                f"psutil is not importable ({exc}); pip install psutil. Without it "
                "there is no process telemetry on this host at all unless Sysmon is "
                "installed.",
            )
        try:
            # Not `process_iter`: a generator that raises on first use would make
            # this probe lie. One concrete call, one concrete answer.
            psutil.Process().pid
            count = len(psutil.pids())
        except Exception as exc:
            return unavailable(
                f"psutil cannot read the process table ({type(exc).__name__}: {exc})",
                fixable_by_user=False,
            )

        notes = [f"{count} processes visible"]
        limits = [
            f"process launches are polled, and the poll interval is the cadence "
            f"({self.cadence_seconds:g}s) plus however long the scan itself takes — "
            "any process that starts and exits inside that window is never seen, "
            "which is most of what an intrusion runs. The measured figure is in "
            "blind_window_seconds on the health board; do not assume it equals the "
            "cadence. " + AUDIT_4688_SETUP
        ]
        if self.track_resource_usage:
            limits.append(
                "resource-usage tracking is on, which re-reads CPU, memory, thread "
                "count and status for every process every cycle — measured at 4.4 s per "
                "poll on a 400-process host, added directly to the blind window above."
            )
        if is_windows() and not is_admin():
            # Unelevated, psutil raises AccessDenied for exe/cmdline/username on
            # every process owned by another account, including all of the system
            # ones. The events still arrive, with a name and a PID and nothing to
            # investigate. Saying so here is the difference between an operator who
            # knows why the command lines are empty and one who assumes the
            # collector is broken.
            limits.append(
                "not elevated, so command line, image path and owner are unavailable "
                "for processes owned by other accounts — those events arrive with a "
                "name and a PID and little else, and the count is in "
                "access_denied_reads. Run from an elevated shell for full attribution."
            )
        return available("; ".join(notes) + ". " + "\n  ".join(limits))

    # ── the blind window ───────────────────────────────────────────────────

    @property
    def blind_window_seconds(self) -> float:
        """How long a process can live and still never be observed. **Measured.**

        Two things go into it, and the first version of this property had only one:

        * the cadence — a process born just after one poll and dead just before the
          next survives the whole interval, so it is the full cadence, not half of it;
        * **the duration of the poll itself.** :meth:`Collector.run` sleeps
          ``cadence_seconds`` *after* the cycle returns, so the interval between two
          poll starts is the cadence plus however long the scan took. When the scan
          took 3.8 s on a 2 s cadence, this property returned ``2.0`` and the true
          figure was ``5.8`` — the collector under-reported its own blindness by a
          factor of three, in the one number an operator would use to decide whether
          process coverage was adequate.

        So the poll is timed and the measurement is used. Before the first poll there
        is nothing to measure and this returns the cadence alone, which is a floor.
        """
        return self.cadence_seconds + self._poll_seconds

    @property
    def blind_window_seconds_worst(self) -> float:
        """The same figure from the slowest *steady-state* poll, not the last one.

        The slow polls are the ones that matter — a scan that is usually 1 ms and
        occasionally 4 s is blind for 4 s at exactly the moment the host is busy,
        which is also when something is most likely to be running.

        The first poll is excluded, and is reported on its own as
        ``first_poll_seconds``. It reads every field of every process and hashes every
        executable, so it is slow by construction; folding it in would leave this
        number pinned at a startup cost where it could never register a regression.
        """
        return self.cadence_seconds + self._poll_seconds_worst

    # ── polling ────────────────────────────────────────────────────────────

    async def poll(self) -> list[dict[str, Any]]:
        """Two passes: identity for everything, detail only for what is new.

        The first version of this method read all twelve fields for every process
        every cycle. Measured, that took **3.8 seconds** for ~390 processes — and
        since :meth:`Collector.run` sleeps the cadence *after* the cycle returns, a
        collector advertising a 2 s cadence was actually blind for 5.8 s at a stretch.
        A process spawned and reaped inside that window produced no launch event and
        no termination event: not a delayed record, no record. It was reproducible —
        a ``python -c "time.sleep(3)"`` started between two polls was never seen at
        all, because the *scan* outlived the process.

        Splitting the passes fixes it at the root. The identity pass is
        ``(pid, create_time)`` and nothing else, which measures at **1 ms**; the
        expensive read then runs only for keys absent from :attr:`_seen`, which in
        steady state is nought to a handful. Termination needs no read whatsoever —
        the record is already held, which is the only reason a dead process can be
        described at all.
        """
        import psutil

        started_at = self.clock()
        now = started_at
        # ── pass 1: identity ──────────────────────────────────────────────
        # The Process objects are kept, not just their keys: pass 2 reads through the
        # same object rather than re-resolving the PID, which would reopen a handle
        # and — worse — could resolve to a *different* process if the PID were reused
        # between the two passes.
        live: dict[tuple[int, float], Any] = {}
        substituted: set[tuple[int, float]] = set()
        boot = self._boot_time()
        for proc in psutil.process_iter(attrs=None):
            try:
                pid = proc.pid
                created = proc.create_time()
            except psutil.NoSuchProcess:
                # Exited between the listing and the read. Counted, because a host
                # where this happens constantly is a host churning through
                # short-lived processes — which is itself worth knowing, and is the
                # signature of both a build and a script-driven intrusion.
                self.vanished_mid_read += 1
                continue
            except psutil.AccessDenied:
                self.access_denied += 1
                continue
            except Exception:
                self.vanished_mid_read += 1
                continue
            if pid is None or created is None:
                # Without both halves of the identity this record cannot be diffed
                # safely; a PID with no creation time would collide with whatever
                # reuses that PID next.
                self.vanished_mid_read += 1
                continue
            key = (int(pid), float(created))
            if created == 0.0 and boot:
                # Windows reports create_time 0 for the two kernel pseudo-processes,
                # PID 0 (System Idle Process) and PID 4 (System). Zero fails schema
                # validation — the event model rejects any timestamp before 2000 —
                # so left alone these two are dropped on every run.
                #
                # Dropping them is the wrong answer. PID 4 is where kernel-mode
                # activity and SMB traffic are attributed, and `System` is a name
                # malware masquerades as; a process table with a permanent hole at
                # PID 4 cannot answer questions about either. Boot time is not a
                # guess here either — the kernel processes *do* start at boot — so
                # the substitution is the accurate value, and it is recorded on the
                # event rather than applied quietly.
                key = (int(pid), float(boot))
                substituted.add(key)
            live[key] = proc

        # ── pass 2: detail, for new processes only ────────────────────────
        # Survivors keep the record read when they were first seen. Those fields do
        # not change, so this is the same answer for less work — and it is the answer
        # that survives the process becoming unreadable later.
        current: dict[tuple[int, float], dict[str, Any]] = {}
        fresh: list[dict[str, Any]] = []
        for key, proc in live.items():
            prior = self._seen.get(key)
            if prior is not None:
                current[key] = prior
                continue
            info = self._read_detail(proc, key)
            if info is None:
                continue
            if key in substituted:
                info["_create_time_from_boot"] = True
            current[key] = info
            fresh.append(info)

        if self.track_resource_usage:
            self._refresh_volatile(live, current)

        payloads: list[dict[str, Any]] = []
        # pid → record, built once over the whole snapshot. Parent resolution needs it
        # for every new process, and a linear scan per child is 160,000 comparisons on
        # a 400-process host — paid for nothing, since the index is one pass.
        by_pid = {pid: info for (pid, _created), info in current.items()}

        if self._first_poll:
            if self.emit_baseline:
                payloads.extend(self._baseline(current, by_pid, now))
            self._first_poll = False
            first = True
        else:
            first = False
            for info in fresh:
                payloads.append(self._launch(info, by_pid, now))
                self.launches += 1
            for key, info in self._seen.items():
                if key not in current:
                    payloads.append(self._terminate(info, now))
                    self.terminations += 1

        # One cycle of memory for the dead, keyed by PID, so an orphaned child can
        # still name its parent. Replaced rather than merged: two cycles of memory
        # would let a PID recycled twice resolve to the wrong generation, which is
        # the bug this whole mechanism exists to avoid.
        self._recent_dead = {
            key[0]: info for key, info in self._seen.items() if key not in current
        }
        self._seen = current
        self._last_poll_at = now
        self._poll_seconds = max(0.0, self.clock() - started_at)
        if first:
            # The first poll reads every field of every process and hashes every
            # distinct executable on the host — measured at 7.2 s here against 1 ms
            # for a steady-state poll. It is recorded separately rather than folded
            # into the worst case: left in, it would pin `poll_seconds_worst` at a
            # startup figure forever, and a steady-state poll that later regressed
            # from 1 ms to 3 s would never move the number an operator watches.
            self._first_poll_seconds = self._poll_seconds
        else:
            self._poll_seconds_worst = max(self._poll_seconds_worst, self._poll_seconds)
        return payloads

    def _boot_time(self) -> float:
        """System boot time, cached. ``0.0`` if psutil cannot say.

        Cached because it cannot change while the process runs, and consulted once per
        poll rather than once per process. Returning ``0.0`` on failure is deliberate:
        the caller only substitutes when it gets a usable value, so a failure here
        leaves the kernel pseudo-processes to be rejected by schema validation — a
        visible loss of two records — rather than stamping them with a wrong time.
        """
        if self._boot_time_cache is None:
            try:
                import psutil

                self._boot_time_cache = float(psutil.boot_time())
            except Exception:
                self._boot_time_cache = 0.0
        return self._boot_time_cache

    def _read_detail(
        self, proc: Any, key: tuple[int, float]
    ) -> dict[str, Any] | None:
        """Every field, for a process seen for the first time. ``None`` if it is gone.

        ``ad_value=None`` turns a per-field ``AccessDenied`` into a ``None`` rather
        than an exception, which is what makes a single ``as_dict`` call viable at all
        — and also what makes the denial invisible unless it is counted here.
        """
        import psutil

        try:
            info = proc.as_dict(attrs=list(_FIELDS), ad_value=None)
        except psutil.NoSuchProcess:
            self.vanished_mid_read += 1
            return None
        except psutil.AccessDenied:
            self.access_denied += 1
            return None
        except Exception:
            self.vanished_mid_read += 1
            return None
        # The identity came from pass 1 and is authoritative: as_dict could return a
        # pid/create_time read a moment later, and disagreement between the diff key
        # and the record it points at is how a launch gets filed under the wrong
        # process.
        info["pid"], info["create_time"] = key[0], key[1]
        if info.get("exe") is None or info.get("cmdline") is None:
            self.access_denied += 1
        return info

    def _refresh_volatile(
        self,
        live: dict[tuple[int, float], Any],
        current: dict[tuple[int, float], dict[str, Any]],
    ) -> None:
        """Re-read the four changing fields for every live process. ~4.4 s per cycle.

        Only called when ``track_resource_usage=True``. The records in :attr:`_seen`
        are mutated in place, so a termination on the next cycle reports counters read
        one cycle before the exit rather than at launch.

        This is the expensive path by a wide margin — see :data:`_VOLATILE_FIELDS` for
        the per-field measurements — and enabling it widens the blind window by
        roughly its own cost. :attr:`blind_window_seconds` measures that rather than
        assuming it, so the trade shows up on the health board instead of in a
        docstring nobody reads.
        """
        import psutil

        for key, proc in live.items():
            info = current.get(key)
            if info is None:
                continue
            try:
                info.update(proc.as_dict(attrs=list(_VOLATILE_FIELDS), ad_value=None))
            except psutil.NoSuchProcess:
                self.vanished_mid_read += 1
            except psutil.AccessDenied:
                self.access_denied += 1
            except Exception:
                self.vanished_mid_read += 1
            else:
                info["_volatile_read_at"] = self.clock()

    # ── event construction ─────────────────────────────────────────────────

    def _baseline(
        self,
        current: dict[tuple[int, float], dict[str, Any]],
        by_pid: dict[int, dict[str, Any]],
        now: float,
    ) -> list[dict[str, Any]]:
        """The process table as found at start, labelled as an inventory.

        These are emitted with ``activity_id=1`` and their *real* creation times,
        which is accurate — the launch did happen then — but they were not
        *observed*, and a restart of this collector would otherwise look like several
        hundred simultaneous process launches. The ``baseline_snapshot`` label is how
        a detection rule tells the difference; every rule that fires on process
        creation must exclude it or it will alert on every restart.

        Dropping them instead was the alternative and is worse: an investigation that
        starts an hour after the collector does still needs to know what was already
        running, and a process that started before CYPHRA is the most likely place
        for something that was there first.
        """
        out: list[dict[str, Any]] = []
        for info in current.values():
            payload = self._launch(info, by_pid, now)
            payload["metadata_labels"] = ["process_table", "baseline_snapshot"]
            payload.setdefault("soc_notes", []).append(
                "baseline inventory: this process was already running when the "
                "collector started, so its launch was not observed — the time is its "
                "real creation time, from the OS, not an observation time"
            )
            out.append(payload)
            self.baseline_emitted += 1
        return out

    def _launch(
        self,
        info: dict[str, Any],
        by_pid: dict[int, dict[str, Any]],
        now: float,
    ) -> dict[str, Any]:
        created = float(info["create_time"])
        pid = int(info["pid"])
        exe = info.get("exe") or ""
        cmdline = info.get("cmdline")
        notes: list[str] = []

        payload: dict[str, Any] = {
            "time": created,
            "class_uid": int(ClassUid.PROCESS_ACTIVITY),
            "activity_id": 1,  # Launch
            "severity_id": int(Severity.INFORMATIONAL),
            "process_pid": pid,
            "process_name": info.get("name") or "",
            "process_created_time": created,
            "device_hostname": _hostname(),
            "metadata_labels": ["process_table"],
            # `(pid, create_time)` written out as the identity it is, so a
            # correlation joining on process identity across a PID recycle joins on
            # something that is actually unique.
            "process_uid": f"{_hostname()}:{pid}:{created:.6f}",
            "metadata_uid": f"{_hostname()}:{pid}:{created:.6f}:launch",
        }
        if exe:
            payload["process_path"] = exe
            payload["process_file_path"] = exe
            payload["process_file_name"] = exe.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if cmdline:
            payload["process_cmd_line"] = " ".join(str(c) for c in cmdline)
        elif cmdline is None:
            notes.append(
                "command line unavailable (access denied) — this process is owned by "
                "another account and this collector is not elevated"
            )
        if info.get("cwd"):
            payload["process_working_directory"] = info["cwd"]
        if info.get("_create_time_from_boot"):
            notes.append(
                "creation time is the system boot time, substituted because Windows "
                f"reports create_time 0 for PID {pid} — a kernel pseudo-process that "
                "does start at boot. The value is accurate to the second the kernel "
                "started, not to this process's own launch, which the OS does not "
                "expose. Do not read a boot-time process launch as a new process."
            )
        if info.get("num_threads") is not None:
            payload["unmapped"] = {"num_threads": info["num_threads"]}
        if info.get("status"):
            payload.setdefault("unmapped", {})["process_status"] = info["status"]

        user = info.get("username")
        if user:
            domain, _, account = str(user).rpartition("\\")
            payload["actor_user_name"] = account or str(user)
            if domain:
                payload["actor_user_domain"] = domain

        self._attach_parent(payload, info, by_pid, created, notes)
        if exe and self.hash_executables:
            self._attach_hashes(payload, exe, notes)

        if info.get("memory_info") is not None:
            rss = getattr(info["memory_info"], "rss", None)
            if rss is not None:
                payload.setdefault("unmapped", {})["memory_rss_bytes"] = int(rss)
        if notes:
            payload["soc_notes"] = notes
        return payload

    def _attach_parent(
        self,
        payload: dict[str, Any],
        info: dict[str, Any],
        by_pid: dict[int, dict[str, Any]],
        child_created: float,
        notes: list[str],
    ) -> None:
        """Resolve ppid to a named parent, or say honestly that it could not be.

        Three outcomes, all of them explicit:

        * the parent is alive, or died within the last cycle and is remembered;
        * the PID resolves but to a process created *after* its supposed child,
          which means the PID was recycled — reported as unresolved with the
          contradiction stated, because naming it would attach a wrong parent to a
          process tree and every lateral-movement chain built from that tree would
          be wrong in a way nothing downstream could detect;
        * the PID does not resolve at all, which is the normal case for a parent
          that exited more than one cycle ago.
        """
        ppid = info.get("ppid")
        if ppid is None:
            return
        ppid = int(ppid)
        payload["process_parent_pid"] = ppid
        payload["actor_process_pid"] = ppid
        if ppid == 0:
            # The System Idle Process is the parent of the kernel, and nothing else.
            payload["actor_process_name"] = "System Idle Process"
            return

        parent: dict[str, Any] | None = by_pid.get(ppid)
        source = "live"
        if parent is None:
            parent = self._recent_dead.get(ppid)
            source = "exited within the last cycle"

        if parent is None:
            self.parent_unresolved += 1
            notes.append(
                f"parent pid {ppid} could not be resolved to a process — it exited "
                "before this cycle, so the parent name and command line are unknown "
                "rather than guessed"
            )
            return

        pcreated = float(parent.get("create_time") or 0.0)
        if pcreated > child_created + 0.001:
            # The parent cannot have been created after its child. Either the PID was
            # recycled between the child's launch and this poll, or the child forged
            # its parent PID (T1134.004). Both are indistinguishable here.
            self.parent_pid_recycled += 1
            self.parent_unresolved += 1
            notes.append(
                f"parent pid {ppid} resolves to a process created "
                f"{pcreated - child_created:.3f}s *after* this one, so that PID has "
                "been recycled (or the parent PID was spoofed) — the parent is "
                "reported as unknown rather than attributing this process to the "
                "wrong tree"
            )
            return

        payload["actor_process_name"] = parent.get("name") or ""
        payload["process_parent_name"] = parent.get("name") or ""
        if parent.get("exe"):
            payload["actor_process_path"] = parent["exe"]
            payload["actor_process_file_path"] = parent["exe"]
        if parent.get("cmdline"):
            line = " ".join(str(c) for c in parent["cmdline"])
            payload["actor_process_cmd_line"] = line
            payload["process_parent_cmd_line"] = line
        payload["actor_process_uid"] = f"{_hostname()}:{ppid}:{pcreated:.6f}"
        if source != "live":
            notes.append(f"parent pid {ppid} {source}; resolved from the previous cycle")

    def _attach_hashes(self, payload: dict[str, Any], exe: str, notes: list[str]) -> None:
        """SHA-256 of the image, cached on ``(path, size, mtime)``.

        The cache key includes size and mtime rather than being just the path, so a
        binary replaced in place — which is what a supply-chain compromise and a
        DLL-for-EXE swap both look like — is hashed again rather than served from the
        cache under its old digest. That is the whole reason this is not keyed on
        path alone.

        Lower-case hex, to agree with the schema's digest validators and with every
        intel feed, for the same reason ``parse_hashes`` does it.
        """
        import hashlib
        from pathlib import Path

        try:
            st = Path(exe).stat()
        except OSError as exc:
            self.hash_failed += 1
            notes.append(f"image not hashable: {type(exc).__name__} reading {exe}")
            return
        key = (exe, st.st_size, st.st_mtime)
        cached = self._hash_cache.get(key)
        if cached is not None:
            self.hashes_from_cache += 1
            payload.update(cached)
            return
        if st.st_size > MAX_HASH_BYTES:
            self.hash_skipped_too_big += 1
            notes.append(
                f"image not hashed: {st.st_size} bytes exceeds the {MAX_HASH_BYTES} "
                "byte cap, so the read was skipped rather than stalling the cycle"
            )
            return
        digest = hashlib.sha256()
        try:
            with open(exe, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            self.hash_failed += 1
            notes.append(f"image not hashable: {type(exc).__name__} reading {exe}")
            return
        value = {"process_file_sha256": digest.hexdigest().lower(), "process_file_size": st.st_size}
        self.hashes_computed += 1
        if len(self._hash_cache) >= HASH_CACHE_SIZE:
            # Insertion-ordered dict, so the first key is the oldest. Evicting one
            # per insert keeps the bound without a periodic sweep.
            self._hash_cache.pop(next(iter(self._hash_cache)))
        self._hash_cache[key] = value
        payload.update(value)

    def _terminate(self, info: dict[str, Any], now: float) -> dict[str, Any]:
        """A process present last cycle and absent now.

        ``time`` is *this* poll, not the last one, and the note says why: the exit
        happened somewhere in the interval and the only honest statement is which
        interval it was. Timing it at the previous poll would claim a precision the
        method does not have, and a correlation window built on that claim would
        exclude events that belong in it.
        """
        created = float(info["create_time"])
        pid = int(info["pid"])
        cpu = info.get("cpu_times")
        payload: dict[str, Any] = {
            "time": now,
            "class_uid": int(ClassUid.PROCESS_ACTIVITY),
            "activity_id": 2,  # Terminate
            "severity_id": int(Severity.INFORMATIONAL),
            "process_pid": pid,
            "process_name": info.get("name") or "",
            "process_created_time": created,
            "process_uid": f"{_hostname()}:{pid}:{created:.6f}",
            "metadata_uid": f"{_hostname()}:{pid}:{created:.6f}:terminate",
            "start_time": created,
            "end_time": now,
            # OCSF `duration` is an integer count of milliseconds, not a float, and
            # pydantic rejects a fractional one outright rather than truncating —
            # which is the correct strictness, since a silently truncated duration is
            # a duration nobody knows is approximate. Rounded, not floored: a 999.7 ms
            # process did not run for 999 ms.
            "duration": int(round(max(0.0, (now - created) * 1000.0))),
            "device_hostname": _hostname(),
            "metadata_labels": ["process_table"],
            "soc_notes": [
                "exit observed by absence from the process table, so it happened "
                f"between {self._last_poll_at:.3f} and {now:.3f} — the event is "
                "stamped at the later bound because that is when it was known"
            ],
        }
        if info.get("exe"):
            payload["process_path"] = info["exe"]
            payload["process_file_path"] = info["exe"]
        if info.get("cmdline"):
            payload["process_cmd_line"] = " ".join(str(c) for c in info["cmdline"])
        # Resource accounting, but only where it was actually measured. Without
        # `track_resource_usage` the counters in `info` are the ones read when the
        # process was first seen, so a lifetime CPU computed from them would be
        # approximately zero for every process on the host — a plausible-looking
        # number that is purely an artifact of when it was sampled. An absent field
        # with a note is recoverable; a wrong number that looks right is not, because
        # nothing downstream can tell it from a genuinely idle process.
        if cpu is not None and self.track_resource_usage:
            total = (getattr(cpu, "user", 0.0) or 0.0) + (getattr(cpu, "system", 0.0) or 0.0)
            lifetime = max(1e-6, now - created)
            read_at = info.get("_volatile_read_at")
            unmapped: dict[str, Any] = {
                "cpu_seconds_total": round(total, 6),
                # Averaged over the *whole* lifetime rather than the last interval:
                # for a process that has already exited that is the only window
                # there is, and a per-interval figure would be undefined.
                "cpu_percent_lifetime": round(100.0 * total / lifetime, 3),
            }
            if read_at:
                # The counters are from the last poll before the exit, never from the
                # exit itself — a dead process cannot be read. Saying how stale they
                # are is what stops the figure being taken as final.
                unmapped["cpu_sampled_seconds_before_exit"] = round(now - read_at, 3)
            payload["unmapped"] = unmapped
        elif cpu is not None:
            payload["soc_notes"].append(
                "no CPU or memory figures: this collector does not refresh resource "
                "counters each cycle (it costs ~4.4 s per poll on this host, which is "
                "added to the blind window), so the only values held are from when the "
                "process was first seen and a lifetime average computed from them "
                "would read as idle regardless of what the process did. Construct with "
                "track_resource_usage=True to measure it."
            )
        return payload

    # ── reporting ──────────────────────────────────────────────────────────

    def stats_extra(self) -> dict[str, Any]:
        return {
            "processes_tracked": len(self._seen),
            "launches": self.launches,
            "terminations": self.terminations,
            "baseline_emitted": self.baseline_emitted,
            # The honest headline: everything shorter-lived than this is invisible.
            # Both figures, because the average is the reassuring one and the worst
            # case is the one an intrusion runs in.
            "blind_window_seconds": round(self.blind_window_seconds, 3),
            "blind_window_seconds_worst": round(self.blind_window_seconds_worst, 3),
            "poll_seconds_last": round(self._poll_seconds, 4),
            "poll_seconds_worst": round(self._poll_seconds_worst, 4),
            "first_poll_seconds": round(self._first_poll_seconds, 4),
            "resource_usage_tracked": self.track_resource_usage,
            "vanished_mid_read": self.vanished_mid_read,
            "access_denied_reads": self.access_denied,
            "parent_unresolved": self.parent_unresolved,
            "parent_pid_recycled": self.parent_pid_recycled,
            "hashes_computed": self.hashes_computed,
            "hashes_from_cache": self.hashes_from_cache,
            "hash_cache_entries": len(self._hash_cache),
            "hash_skipped_too_big": self.hash_skipped_too_big,
            "hash_failed": self.hash_failed,
        }


_HOSTNAME = ""


def _hostname() -> str:
    global _HOSTNAME
    if not _HOSTNAME:
        import socket

        try:
            _HOSTNAME = socket.gethostname()
        except Exception:
            _HOSTNAME = "unknown"
    return _HOSTNAME


__all__ = [
    "AUDIT_4688_SETUP",
    "HASH_CACHE_SIZE",
    "MAX_HASH_BYTES",
    "ProcessCollector",
]
