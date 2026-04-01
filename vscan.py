#!/usr/bin/env python3

"""Scan one directory tree and runtime network state using JSON-defined rules."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import Pattern


@dataclass(frozen=True)
class Rule:
    """Represent one validated scan rule."""

    # Keep the original rule identifier so failures can point back to the JSON config.
    rule_id: str
    # Use the rule type to decide whether this rule is file-based or runtime-based.
    rule_type: str
    # Reuse the human-readable label in both streaming output and the final summary.
    label: str
    # Store the raw regex pattern so the scanner can hand it to ripgrep unchanged.
    pattern: str
    # Keep the exact path for filesystem presence checks.
    target_path: str
    # Limit text scans to matching file names or relative paths only.
    include_globs: tuple[str, ...]
    # Allow wildcard-heavy rules to carve out unwanted matches after include_globs matched.
    exclude_globs: tuple[str, ...]
    # Compile once during config load so network rules can reuse the regex cheaply.
    compiled_pattern: Pattern[str] | None


@dataclass(frozen=True)
class MatchRecord:
    """Represent one text-search match."""

    # Keep the label next to each match so merged worker results stay self-describing.
    label: str
    # Store the exact location string that will be printed to the terminal.
    location: str


@dataclass
class ScanResult:
    """Store matches and queued file counts for one scan path."""

    # Preserve the requested root for final reporting.
    scan_path: Path
    # Bucket streamed matches by rule label so final printing can stay deterministic.
    matches_by_label: dict[str, list[str]]
    # Track how many candidate files each text rule was applied to.
    checked_counts_by_label: dict[str, int]


class StatusReporter:
    """Render a single live status line while the scan is running."""

    def __init__(self) -> None:
        """Initialize thread-safe status state."""

        # Serialize status and message output from multiple threads.
        self._status_lock = threading.Lock()

        # Track the current status message for the scan path.
        self._status_message = "starting"

        # Track queued and completed file-scan counts.
        self._scheduled_task_count = 0
        self._completed_task_count = 0

        # Prefer the active terminal for a single-line live status display.
        try:
            self._output_stream = open("/dev/tty", "w", encoding="utf-8", buffering=1)
        except OSError:
            if sys.stdout.isatty():
                self._output_stream = sys.stdout
            elif sys.stderr.isatty():
                self._output_stream = sys.stderr
            else:
                self._output_stream = None

        # Repaint periodically so the user still sees liveness during long searches.
        self._stop_refresh_event = threading.Event()
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)

        if self._output_stream is not None:
            self._refresh_thread.start()

    def update_status(self, status_message: str) -> None:
        """Update the current scan status message."""

        with self._status_lock:
            self._status_message = status_message
            self._render_locked()

    def increment_scheduled_tasks(self) -> None:
        """Increment the number of queued rule tasks."""

        with self._status_lock:
            self._scheduled_task_count += 1
            self._render_locked()

    def increment_completed_tasks(self) -> None:
        """Increment the number of finished rule tasks."""

        with self._status_lock:
            self._completed_task_count += 1
            self._render_locked()

    def print_message(self, message_text: str) -> None:
        """Print a normal output line without corrupting the live status line."""

        with self._status_lock:
            if self._output_stream is not None:
                self._output_stream.write("\r\033[K")
                self._output_stream.flush()

            print(message_text)

            if self._output_stream is not None:
                self._render_locked()

    def finish(self) -> None:
        """Stop the refresh thread and terminate the live status line cleanly."""

        if self._output_stream is None:
            return

        self._stop_refresh_event.set()
        self._refresh_thread.join(timeout=1)

        with self._status_lock:
            self._render_locked()
            self._output_stream.write("\n")
            self._output_stream.flush()

        if self._output_stream not in (sys.stdout, sys.stderr):
            self._output_stream.close()

    def _render_locked(self) -> None:
        """Render the current live status line while holding the lock."""

        if self._output_stream is None:
            return

        rendered_status_line = (
            f"tasks {self._completed_task_count}/{self._scheduled_task_count}"
            f" | {self._status_message}"
        )
        clipped_status_line = self._clip_status_line(rendered_status_line)
        self._output_stream.write(f"\r\033[K{clipped_status_line}")
        self._output_stream.flush()

    def _refresh_loop(self) -> None:
        """Repaint the live status line periodically."""

        while not self._stop_refresh_event.wait(0.5):
            with self._status_lock:
                self._render_locked()

    def _clip_status_line(self, rendered_status_line: str) -> str:
        """Clip the live status line so it stays on one terminal row."""

        terminal_width = shutil.get_terminal_size(fallback=(120, 24)).columns

        if terminal_width < 8 or len(rendered_status_line) <= terminal_width - 1:
            return rendered_status_line

        visible_width = terminal_width - 1
        retained_suffix_width = max(visible_width - 3, 1)
        return f"...{rendered_status_line[-retained_suffix_width:]}"


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments and validate the basic constraints."""

    # Keep the CLI small and explicit so the tool fails fast on missing inputs.
    argument_parser = argparse.ArgumentParser(
        description="Scan one directory tree and runtime network state using JSON-defined rules.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    argument_parser.add_argument(
        "--path",
        required=True,
        help="Path to the root directory to scan recursively.",
    )
    argument_parser.add_argument(
        "--rules",
        required=True,
        help="Path to the JSON rules file.",
    )
    argument_parser.add_argument(
        "--threads",
        type=int,
        default=3,
        help="Total worker threads to use.",
    )
    argument_parser.add_argument(
        "--match-timeout-seconds",
        type=float,
        default=15.0,
        help="Maximum seconds allowed for one file-rule text match.",
    )
    parsed_arguments = argument_parser.parse_args()

    if parsed_arguments.threads < 1:
        raise SystemExit("ERROR: --threads must be at least 1.")
    if parsed_arguments.match_timeout_seconds <= 0:
        raise SystemExit("ERROR: --match-timeout-seconds must be greater than 0.")

    return parsed_arguments


def validate_scan_path(path_argument: str) -> Path:
    """Resolve the scan path and fail fast when it is not a directory."""

    resolved_scan_path = Path(path_argument).expanduser().resolve()

    if not resolved_scan_path.is_dir():
        raise SystemExit(
            f"ERROR: Scan path does not exist or is not a directory: {resolved_scan_path}"
        )

    return resolved_scan_path


def load_rules_file(rules_path: Path) -> dict:
    """Load the JSON rules file and fail fast on invalid JSON."""

    try:
        rules_file_contents = rules_path.read_text(encoding="utf-8")
    except OSError as error:
        raise SystemExit(f"ERROR: Failed to read rules file {rules_path}: {error}") from error

    try:
        return json.loads(rules_file_contents)
    except json.JSONDecodeError as error:
        raise SystemExit(f"ERROR: Invalid JSON in rules file {rules_path}: {error}") from error


def load_rules(rules_path: Path) -> list[Rule]:
    """Load, validate, and normalize scan rules."""

    # Validate the whole rules file up front so worker threads never deal with bad config.
    rules_file_object = load_rules_file(rules_path)
    raw_rules = rules_file_object.get("rules")

    if not isinstance(raw_rules, list):
        raise SystemExit("ERROR: Rules file must contain a top-level `rules` array.")

    normalized_rules: list[Rule] = []

    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            raise SystemExit("ERROR: Every rule must be a JSON object.")

        # Normalize every required field once so downstream code can stay simple.
        rule_id = str(raw_rule.get("id", "")).strip()
        label = str(raw_rule.get("label", "")).strip()
        rule_type = str(raw_rule.get("type", "")).strip()
        pattern = str(raw_rule.get("pattern", "")).strip()
        target_path = str(raw_rule.get("target_path", "")).strip()

        if not rule_id or not rule_type or not label:
            raise SystemExit(
                "ERROR: Every rule must define non-empty `id`, `type`, and `label`."
            )

        if rule_type not in {"text_pattern", "network_connection", "path_exists"}:
            raise SystemExit(f"ERROR: Unsupported rule type `{rule_type}`.")

        compiled_pattern: Pattern[str] | None = None
        if rule_type in {"text_pattern", "network_connection"}:
            if not pattern:
                raise SystemExit(
                    f"ERROR: Rule {rule_id} must define non-empty `pattern` for type `{rule_type}`."
                )
            try:
                # Compile during load time so invalid regex never reaches execution.
                compiled_pattern = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error as error:
                raise SystemExit(f"ERROR: Invalid regex for rule {rule_id}: {error}") from error
        elif not target_path:
            raise SystemExit(
                f"ERROR: Rule {rule_id} must define non-empty `target_path` for type `path_exists`."
            )

        # Only text rules need file globs; network rules operate on runtime snapshots instead.
        include_globs = ()
        exclude_globs = ()

        if rule_type == "text_pattern":
            include_globs = tuple(
                str(include_glob) for include_glob in raw_rule.get("include_globs", [])
            )

            if not include_globs:
                raise SystemExit(
                    f"ERROR: Rule {rule_id} must define a non-empty `include_globs` array."
                )

            exclude_globs = tuple(
                str(exclude_glob) for exclude_glob in raw_rule.get("exclude_globs", [])
            )

        normalized_rules.append(
            Rule(
                rule_id=rule_id,
                rule_type=rule_type,
                label=label,
                pattern=pattern,
                target_path=target_path,
                include_globs=include_globs,
                exclude_globs=exclude_globs,
                compiled_pattern=compiled_pattern,
            )
        )

    return normalized_rules


def ensure_required_tools_exist(rules: list[Rule]) -> None:
    """Fail fast when required runtime tools are missing."""

    # Keep tool validation centralized so execution paths do not need repeated checks.
    if shutil.which("python3") is None:
        raise SystemExit("ERROR: `python3` is required but was not found.")

    uses_network_rules = any(rule.rule_type == "network_connection" for rule in rules)

    if uses_network_rules and shutil.which("lsof") is None:
        raise SystemExit("ERROR: `lsof` is required by network_connection rules but was not found.")


def initialize_match_map(rules: list[Rule]) -> dict[str, list[str]]:
    """Create the stable match map from the configured rule labels."""

    # Pre-create every label bucket so missing matches still produce stable output sections.
    return {rule.label: [] for rule in rules}


def initialize_checked_count_map(rules: list[Rule]) -> dict[str, int]:
    """Create the stable checked-count map from the configured rule labels."""

    # Count scanned candidates separately from found matches to aid debugging.
    return {f"{rule.label} checked": 0 for rule in rules}


def build_scan_result(scan_path: Path, rules: list[Rule]) -> ScanResult:
    """Create the initial scan result container."""

    return ScanResult(
        scan_path=scan_path,
        matches_by_label=initialize_match_map(rules),
        checked_counts_by_label=initialize_checked_count_map(rules),
    )


def read_text_file(file_path: Path) -> str:
    """Read a file as text while tolerating mixed encodings."""

    # Ignore decoding errors so strange byte sequences do not abort an otherwise valid scan.
    return file_path.read_text(encoding="utf-8", errors="ignore")


def build_relative_path(file_path: Path, scan_path: Path) -> str:
    """Build a stable scan-relative POSIX path for glob matching."""

    return file_path.relative_to(scan_path).as_posix()


def shorten_status_path(path_text: str, max_length: int = 80) -> str:
    """Shorten a displayed path so status updates remain readable."""

    if len(path_text) <= max_length:
        return path_text

    retained_suffix_width = max(max_length - 3, 1)
    return f"...{path_text[-retained_suffix_width:]}"


def is_regular_scan_file(file_path: Path) -> bool:
    """Return whether a path is a regular file safe to queue for scanning."""

    try:
        # Use lstat so symlinks are rejected instead of being followed to unknown targets.
        file_stat_result = file_path.lstat()
    except OSError:
        return False

    # Only queue plain files; skip sockets, devices, FIFOs, and symlinks entirely.
    return stat.S_ISREG(file_stat_result.st_mode)


def rule_matches_file(rule: Rule, relative_file_path: str, file_name: str) -> bool:
    """Return whether a rule should scan a discovered file."""

    # Accept either an exact relative path match or a basename wildcard match.
    include_matches = any(
        fnmatch.fnmatch(relative_file_path, include_glob)
        or fnmatch.fnmatch(file_name, include_glob)
        for include_glob in rule.include_globs
    )

    if not include_matches:
        return False

    # Apply excludes only after the file is already in-scope for the rule.
    exclude_matches = any(
        fnmatch.fnmatch(relative_file_path, exclude_glob)
        or fnmatch.fnmatch(file_name, exclude_glob)
        for exclude_glob in rule.exclude_globs
    )

    return not exclude_matches


def run_text_pattern_rule(
    rule: Rule,
    file_path: Path,
    match_timeout_seconds: float,
) -> list[MatchRecord]:
    """Run one regex text-search rule against one candidate file with ripgrep."""

    # Offload matching to ripgrep so one bad regex/file pair cannot wedge the Python worker.
    completed_process = subprocess.run(
        [
            "rg",
            "--json",
            "--multiline",
            "--pcre2",
            rule.pattern,
            str(file_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=match_timeout_seconds,
    )

    # ripgrep uses exit code 1 for "no matches", which is a normal scan result here.
    if completed_process.returncode not in (0, 1):
        raise RuntimeError(
            f"ripgrep failed for {file_path} and rule {rule.rule_id}: "
            f"{completed_process.stderr.strip()}"
        )

    if completed_process.returncode == 1:
        return []

    match_records: list[MatchRecord] = []

    for output_line in completed_process.stdout.splitlines():
        try:
            # Parse ripgrep JSON events so we can recover the exact line containing the submatch.
            output_event = json.loads(output_line)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Invalid ripgrep JSON output for {file_path}: {error}") from error

        # Ignore non-match events such as begin/end/summary.
        if output_event.get("type") != "match":
            continue

        match_data = output_event.get("data", {})
        line_number = int(match_data.get("line_number", 0))
        matched_text = str(match_data.get("lines", {}).get("text", ""))
        submatches = match_data.get("submatches", [])

        if not matched_text or not submatches:
            continue

        # Use the first submatch offset to print the actual matching line instead of the whole block.
        first_submatch = submatches[0]
        submatch_start = int(first_submatch.get("start", 0))
        line_start_offset = matched_text.rfind("\n", 0, submatch_start) + 1
        line_end_offset = matched_text.find("\n", submatch_start)

        if line_end_offset == -1:
            line_end_offset = len(matched_text)

        matched_line_text = matched_text[line_start_offset:line_end_offset].rstrip("\n")
        line_offset_within_match = matched_text.count("\n", 0, line_start_offset)
        displayed_line_number = line_number + line_offset_within_match

        match_records.append(
            MatchRecord(
                label=rule.label,
                location=f"{file_path}:{displayed_line_number}:{matched_line_text}",
            )
        )

    return match_records


def capture_network_connections() -> str:
    """Capture the current network connection table using lsof."""

    # Capture once per scan so multiple runtime rules reuse the same snapshot consistently.
    completed_process = subprocess.run(
        ["lsof", "-i"],
        check=False,
        capture_output=True,
        text=True,
    )

    if completed_process.returncode not in (0, 1):
        raise RuntimeError(f"lsof failed: {completed_process.stderr.strip()}")

    return completed_process.stdout


def run_network_rule(rule: Rule, network_snapshot: str) -> list[MatchRecord]:
    """Run one runtime network rule against the captured lsof snapshot."""

    match_records: list[MatchRecord] = []

    for output_line in network_snapshot.splitlines():
        # Test each line independently because lsof output is already line-oriented.
        if rule.compiled_pattern is None or rule.compiled_pattern.search(output_line) is None:
            continue

        match_records.append(MatchRecord(label=rule.label, location=output_line))

    return match_records


def run_path_exists_rule(rule: Rule) -> list[MatchRecord]:
    """Run one filesystem presence rule against its configured target path."""

    target_path = Path(rule.target_path).expanduser()

    if not target_path.exists():
        return []

    return [MatchRecord(label=rule.label, location=str(target_path.resolve()))]


def append_match_records(scan_result: ScanResult, match_records: list[MatchRecord]) -> None:
    """Append finished match records into the result bucket."""

    # Merge worker output under the owning rule label so final reporting stays grouped.
    for match_record in match_records:
        scan_result.matches_by_label[match_record.label].append(match_record.location)


def stream_match_records(status_reporter: StatusReporter, match_records: list[MatchRecord]) -> None:
    """Print findings immediately when they are discovered."""

    for match_record in match_records:
        status_reporter.print_message(f"FOUND: {match_record.label}")
        status_reporter.print_message(f"LOCATION: {match_record.location}")
        status_reporter.print_message("")


def print_section_header(section_title: str) -> None:
    """Print a stable section header."""

    print(f"\n== {section_title} ==")


def print_label_results(label: str, locations: list[str]) -> int:
    """Print all match results for one configured label."""

    if not locations:
        print(f"NOT FOUND: {label}\n")
        return 0

    for location in sorted(locations):
        print(f"FOUND: {label}")
        print(f"LOCATION: {location}\n")

    return len(locations)


def print_scan_results(scan_result: ScanResult, rules: list[Rule]) -> int:
    """Print configured results for the scan path and return the match count."""

    total_match_count = 0
    grouped_rules_by_section: dict[str, list[Rule]] = {}

    for rule in rules:
        # Derive display sections from rule type so the JSON schema can stay minimal.
        if rule.rule_type == "text_pattern":
            section_title = "Package Files"
        elif rule.rule_type == "network_connection":
            section_title = "Active Network Connections"
        else:
            section_title = "Filesystem Paths"
        grouped_rules_by_section.setdefault(section_title, []).append(rule)

    print_section_header("Validating Input")
    print(f"Scanning directory: {scan_result.scan_path}")

    for section_title, section_rules in grouped_rules_by_section.items():
        print_section_header(section_title)

        for rule in section_rules:
            total_match_count += print_label_results(
                rule.label,
                scan_result.matches_by_label[rule.label],
            )

    print_section_header("Summary")

    for rule in rules:
        print(
            f"{rule.label} found: "
            f"{len(scan_result.matches_by_label[rule.label])}"
        )

    print(f"Total matches: {total_match_count}")
    return total_match_count


def submit_scan_task(
    pending_scan_queue: Queue[tuple[Path, tuple[Rule, ...]] | None],
    scan_result: ScanResult,
    status_reporter: StatusReporter,
    file_path: Path,
    matching_rules: tuple[Rule, ...],
) -> None:
    """Queue one candidate file scan and update progress counters immediately."""

    # Increment per-rule checked counts before queuing so the summary reflects attempted scans.
    for matching_rule in matching_rules:
        scan_result.checked_counts_by_label[f"{matching_rule.label} checked"] += 1

    # Queue the file once with all matching rules so the worker can scan that file in one pass.
    pending_scan_queue.put((file_path, matching_rules))
    status_reporter.increment_scheduled_tasks()


def worker_loop(
    pending_scan_queue: Queue[tuple[Path, tuple[Rule, ...]] | None],
    scan_result: ScanResult,
    scan_result_lock: threading.Lock,
    status_reporter: StatusReporter,
    failure_state: dict[str, str | None],
    failure_lock: threading.Lock,
    stop_event: threading.Event,
    match_timeout_seconds: float,
) -> None:
    """Process queued file scans until the producer signals completion or failure."""

    while True:
        # Block on the shared queue so worker threads naturally back off when there is no work.
        queued_item = pending_scan_queue.get()

        try:
            if queued_item is None:
                # Use a sentinel to shut workers down once the producer has finished queueing.
                return

            if stop_event.is_set():
                # Stop accepting real work once another thread has already failed.
                continue

            file_path, matching_rules = queued_item
            match_records: list[MatchRecord] = []

            for matching_rule in matching_rules:
                # Run every applicable rule against this file before touching shared result state.
                match_records.extend(
                    run_text_pattern_rule(
                        matching_rule,
                        file_path,
                        match_timeout_seconds,
                    )
                )

            with scan_result_lock:
                # Hold the result lock only while mutating shared scan output structures.
                append_match_records(scan_result, match_records)

            if match_records:
                # Stream matches outside the result mutation step so the lock scope stays small.
                stream_match_records(status_reporter, match_records)

            status_reporter.increment_completed_tasks()
        except Exception as error:
            with failure_lock:
                # Preserve only the first worker error so the main thread gets one clear failure.
                if failure_state["message"] is None:
                    failure_state["message"] = f"Failed to scan queued work item: {error}"
            stop_event.set()
            return
        finally:
            # Always mark the queue item done so Queue.join() cannot hang on worker failure.
            pending_scan_queue.task_done()


def walk_and_queue_files(
    scan_path: Path,
    rules: list[Rule],
    pending_scan_queue: Queue[tuple[Path, tuple[Rule, ...]] | None],
    scan_result: ScanResult,
    status_reporter: StatusReporter,
    stop_event: threading.Event,
) -> None:
    """Walk the scan tree and queue candidate file scans as files are discovered."""

    for current_root, _, file_names in os.walk(scan_path):
        if stop_event.is_set():
            # Stop producing new work as soon as a worker failure or interrupt is signaled.
            return

        current_root_path = Path(current_root)
        relative_root_path = current_root_path.relative_to(scan_path)
        displayed_root_path = (
            "."
            if str(relative_root_path) == "."
            else shorten_status_path(relative_root_path.as_posix())
        )
        status_reporter.update_status(f"scanning {displayed_root_path}")

        for file_name in file_names:
            if stop_event.is_set():
                return

            current_file_path = current_root_path / file_name

            if not is_regular_scan_file(current_file_path):
                continue

            relative_file_path = build_relative_path(current_file_path, scan_path)
            # Resolve all matching rules before queueing so unmatched files are never read.
            matching_rules = tuple(
                rule
                for rule in rules
                if rule_matches_file(rule, relative_file_path, file_name)
            )

            if not matching_rules:
                continue

            submit_scan_task(
                pending_scan_queue,
                scan_result,
                status_reporter,
                current_file_path,
                matching_rules,
            )


def main() -> int:
    """Load configured rules, scan candidate files immediately, and print results."""

    # Resolve and validate all inputs before any background work starts.
    parsed_arguments = parse_arguments()
    validated_scan_path = validate_scan_path(parsed_arguments.path)
    rules_path = Path(parsed_arguments.rules).expanduser().resolve()
    rules = load_rules(rules_path)
    ensure_required_tools_exist(rules)
    # Split rule execution paths early so file workers only see text-based rules.
    text_rules = [rule for rule in rules if rule.rule_type == "text_pattern"]
    network_rules = [rule for rule in rules if rule.rule_type == "network_connection"]
    path_rules = [rule for rule in rules if rule.rule_type == "path_exists"]

    status_reporter = StatusReporter()
    scan_result = build_scan_result(validated_scan_path, rules)
    scan_result_lock = threading.Lock()
    failure_lock = threading.Lock()
    stop_event = threading.Event()
    failure_state: dict[str, str | None] = {"message": None}
    pending_scan_queue: Queue[tuple[Path, tuple[Rule, ...]] | None] = Queue()
    worker_threads: list[threading.Thread] = []

    status_reporter.update_status(f"{validated_scan_path}: starting")

    if network_rules:
        # Evaluate runtime-only checks first because they do not depend on filesystem traversal.
        status_reporter.update_status("checking active network connections")
        network_snapshot = capture_network_connections()

        for network_rule in network_rules:
            # Treat each runtime rule as one checked task in the live progress display.
            scan_result.checked_counts_by_label[f"{network_rule.label} checked"] += 1
            status_reporter.increment_scheduled_tasks()
            match_records = run_network_rule(network_rule, network_snapshot)
            append_match_records(scan_result, match_records)

            if match_records:
                stream_match_records(status_reporter, match_records)

            status_reporter.increment_completed_tasks()

    if path_rules:
        # Run exact filesystem path checks before the directory walk because they are standalone.
        status_reporter.update_status("checking filesystem paths")

        for path_rule in path_rules:
            scan_result.checked_counts_by_label[f"{path_rule.label} checked"] += 1
            status_reporter.increment_scheduled_tasks()
            match_records = run_path_exists_rule(path_rule)
            append_match_records(scan_result, match_records)

            if match_records:
                stream_match_records(status_reporter, match_records)

            status_reporter.increment_completed_tasks()

    for worker_index in range(parsed_arguments.threads):
        # Keep workers daemonized so Ctrl+C can terminate the process even if one worker wedges.
        worker_thread = threading.Thread(
            target=worker_loop,
            args=(
                pending_scan_queue,
                scan_result,
                scan_result_lock,
                status_reporter,
                failure_state,
                failure_lock,
                stop_event,
                parsed_arguments.match_timeout_seconds,
            ),
            daemon=True,
            name=f"scan-worker-{worker_index}",
        )
        worker_thread.start()
        worker_threads.append(worker_thread)

    try:
        try:
            # The producer walks once and pushes matching files to the worker queue immediately.
            walk_and_queue_files(
                validated_scan_path,
                text_rules,
                pending_scan_queue,
                scan_result,
                status_reporter,
                stop_event,
            )

            for _ in worker_threads:
                # Send one sentinel per worker so every worker eventually exits its queue loop.
                pending_scan_queue.put(None)

            # Wait until every queued file has either been processed or failed.
            pending_scan_queue.join()

            if failure_state["message"] is not None:
                raise SystemExit(f"ERROR: {failure_state['message']}")

            status_reporter.update_status(f"{validated_scan_path}: done")
            print_scan_results(scan_result, rules)
            return 0
        except KeyboardInterrupt:
            # Flip the shared stop flag so the producer and workers stop taking new work quickly.
            stop_event.set()
            raise SystemExit("ERROR: Scan interrupted by user.")
    finally:
        # Always tear down the live status line, including on failures and interrupts.
        status_reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
