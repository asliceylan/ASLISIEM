import random
import threading
import time

from backend.engine.rule_engine import run_all_rules
from backend.services import suggestion_service
from backend.services.ingest_service import ingest_raw_log
from backend.simulator.scenario import generate_kill_chain_events


class SimulatorThread(threading.Thread):
    """Owns three jobs of the simulator with a single background thread:
    (1) paces and ingests the next log line from the kill-chain scenario,
    (2) tracks wall-clock time since the last run_all_rules() call and
    re-runs it periodically (not per-event) once new events have landed,
    (3) on a separate, deliberately coarser cadence, runs suggestion_
    service.auto_apply_new_rule_suggestions -- turns newly-detected attack
    patterns straight into real, enabled Rules with no human approval step
    (see that function's docstring for the dedup guarantee). Kept on its
    own interval rather than piggybacking on the rule-check interval
    because it does its own full Event scan on top of run_all_rules'
    (pattern detection over every event, not just rule evaluation) -- at
    the same tight cadence that would double the per-cycle O(N) cost this
    app is already known to scale with.
    Uses threading.Event.wait() instead of time.sleep() so stop() is
    responsive rather than blocking for up to a full pacing interval."""

    def __init__(self, app, tenant_id=None, devices=None, speed_multiplier=1.0,
                 event_interval_range=(10, 25), rule_check_interval_seconds=10,
                 suggestion_check_interval_seconds=30):
        super().__init__(daemon=True)
        self.app = app
        self.tenant_id = tenant_id
        self.devices = devices  # None -> generate_kill_chain_events falls back to topology.DEVICES
        self.speed_multiplier = min(max(speed_multiplier, 1.0), 500.0)
        self.event_interval_range = event_interval_range
        self.rule_check_interval_seconds = rule_check_interval_seconds
        self.suggestion_check_interval_seconds = suggestion_check_interval_seconds
        self._stop_event = threading.Event()
        self._status_lock = threading.Lock()
        self._status = {
            "running": False,
            "current_phase": None,
            "events_generated": 0,
            "rules_auto_created": 0,
            "last_error": None,
        }

    def status(self):
        with self._status_lock:
            return dict(self._status)

    def _record_event(self, phase):
        with self._status_lock:
            self._status["current_phase"] = phase
            self._status["events_generated"] += 1

    def _record_auto_rules(self, count):
        with self._status_lock:
            self._status["rules_auto_created"] += count

    def _record_error(self, message):
        with self._status_lock:
            self._status["last_error"] = message

    def _set_running(self, running):
        with self._status_lock:
            self._status["running"] = running

    def stop(self):
        self._stop_event.set()

    def run(self):
        self._set_running(True)
        rng = random.Random()
        gen = generate_kill_chain_events(rng, devices=self.devices)
        last_rule_check = time.monotonic()
        last_suggestion_check = time.monotonic()
        pending_new_events = 0
        # Tracked separately from pending_new_events: the rule-check block
        # below resets that counter on its own (shorter) interval, which
        # would otherwise starve this block's (longer) interval of ever
        # seeing pending_new_events > 0.
        pending_new_events_for_suggestions = 0

        try:
            while not self._stop_event.is_set():
                item = next(gen)
                with self.app.app_context():
                    try:
                        ingest_raw_log(item["raw_text"], item["device"], tenant_id=self.tenant_id)
                        pending_new_events += 1
                        pending_new_events_for_suggestions += 1
                        self._record_event(item["phase"])
                    except Exception as exc:
                        self._record_error(str(exc))

                    now = time.monotonic()
                    check_interval = max(0.5, self.rule_check_interval_seconds / self.speed_multiplier)
                    if pending_new_events > 0 and (now - last_rule_check) >= check_interval:
                        try:
                            run_all_rules(tenant_id=self.tenant_id)
                        except Exception as exc:
                            self._record_error(f"rule evaluation failed: {exc}")
                        last_rule_check = now
                        pending_new_events = 0

                    suggestion_interval = max(0.5, self.suggestion_check_interval_seconds / self.speed_multiplier)
                    if pending_new_events_for_suggestions > 0 and (now - last_suggestion_check) >= suggestion_interval:
                        try:
                            created = suggestion_service.auto_apply_new_rule_suggestions(tenant_id=self.tenant_id)
                            if created:
                                self._record_auto_rules(len(created))
                        except Exception as exc:
                            self._record_error(f"suggestion automation failed: {exc}")
                        last_suggestion_check = now
                        pending_new_events_for_suggestions = 0

                lo, hi = self.event_interval_range
                sleep_for = max(0.05, random.uniform(lo, hi) / self.speed_multiplier)
                self._stop_event.wait(timeout=sleep_for)
        finally:
            self._set_running(False)
