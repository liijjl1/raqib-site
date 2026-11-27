import threading
import time
from collections import Counter, deque

import numpy as np

from .models import MODEL_KEYS, POLICIES
from .traffic import ATTACK_TYPES, NUM_COLS, live_batch

CHART_W, CHART_H, SPARK_W, SPARK_H = 640, 200, 160, 28


def points(values, width, height, length):
    step = width / max(1, length - 1)
    start = length - len(values)
    return " ".join(f"{(start + i) * step:.1f},{height - v / 100 * height:.1f}" for i, v in enumerate(values))


class LiveMonitor:
    def __init__(self, system, devices, baseline, on_close=None, seed=2026):
        self.system = system
        self.baseline = baseline
        self.on_close = on_close
        self.rng = np.random.default_rng(seed)
        self.lock = threading.Lock()
        self.column_index = {name: i for i, name in enumerate(system.pipeline.columns)}
        self.devices = [dict(device, id=i, attack=None, incident=None, last=None) for i, device in enumerate(devices)]
        self.running, self.speed, self.policy, self.sensitivity, self.auto_attacks = True, 1, "majority", 99.0, True
        self.reset()

    def reset(self):
        with self.lock:
            self.tick = 0
            self.clock = time.monotonic()
            self.next_auto = 8
            self.incidents = []
            self.stats = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "true_incidents": 0, "false_incidents": 0,
                          "launched": 0, "detected": 0, "missed": 0, "detect_times": [], "latency_ms": None}
            for device in self.devices:
                device.update(attack=None, incident=None, last=None, recent=deque(maxlen=3), history=deque(maxlen=90))

    def catch_up(self):
        now = time.monotonic()
        with self.lock:
            due = int((now - self.clock) * self.speed) if self.running else 0
            if due <= 0:
                if not self.running:
                    self.clock = now
                return
            for _ in range(min(due, 5)):
                self.step()
            self.clock = now if due > 5 else self.clock + due / self.speed

    def settings(self):
        return {"running": self.running, "speed": self.speed, "policy": self.policy,
                "sensitivity": self.sensitivity, "auto_attacks": self.auto_attacks}

    def configure(self, running=None, speed=None, policy=None, sensitivity=None, auto_attacks=None):
        with self.lock:
            self.clock = time.monotonic()
            if running is not None:
                self.running = running
            if speed in (1, 2, 4):
                self.speed = speed
            if policy in POLICIES:
                self.policy = policy
            if sensitivity is not None and 80 <= sensitivity <= 99.9:
                self.sensitivity = sensitivity
                self.system.set_sensitivity(sensitivity)
            if auto_attacks is not None:
                self.auto_attacks = auto_attacks
        return self.settings()

    def launch_attack(self, device_id, kind, stealthy=False, duration=30, by=None):
        if kind not in ATTACK_TYPES or not 0 <= device_id < len(self.devices):
            return False
        with self.lock:
            self._launch(self.devices[device_id], kind, stealthy, min(max(duration, 3), 300), by)
        return True

    def stop_attacks(self):
        with self.lock:
            for device in self.devices:
                if device["attack"]:
                    self._end_attack(device)

    def _launch(self, device, kind, stealthy, duration, by=None):
        if device["attack"]:
            self._end_attack(device)
        start = self.tick + 1
        device["attack"] = {"kind": kind, "stealthy": stealthy, "start": start,
                            "end": start + max(3, duration) - 1, "detected": False, "by": by}
        self.stats["launched"] += 1

    def _end_attack(self, device):
        self.stats["detected" if device["attack"]["detected"] else "missed"] += 1
        device["attack"] = None

    def _auto_attack(self):
        if not self.auto_attacks or self.tick < self.next_auto:
            return
        if sum(1 for d in self.devices if d["attack"]) < 2:
            kind = str(self.rng.choice(ATTACK_TYPES))
            pool = [d for d in self.devices if not d["attack"] and not (kind == "Exfiltration" and d["type"] == "camera")]
            device = pool[self.rng.integers(len(pool))]
            self._launch(device, kind, bool(self.rng.random() < 0.3), int(self.rng.integers(14, 28)))
        self.next_auto = self.tick + int(self.rng.integers(16, 38))

    def step(self):
        self.tick += 1
        self._auto_attack()
        for device in self.devices:
            if device["attack"] and self.tick > device["attack"]["end"]:
                self._end_attack(device)
        batch = live_batch(self.rng, self.devices)
        started = time.perf_counter()
        result = self.system.assess(batch, self.policy)
        per_record = (time.perf_counter() - started) * 1000 / len(self.devices)
        old = self.stats["latency_ms"]
        self.stats["latency_ms"] = per_record if old is None else 0.9 * old + 0.1 * per_record
        for i, device in enumerate(self.devices):
            self._update(device, batch.iloc[i], result["risks"][i], float(result["final"][i]),
                         result["errors"][i], result["guess"][i])

    def _update(self, device, record, risks, final, errors, guess):
        attack = device["attack"]
        alarm = final >= 50
        key = ("tp" if attack else "fp") if alarm else ("fn" if attack else "tn")
        self.stats[key] += 1
        device["recent"].append(alarm)
        device["history"].append({"risks": risks.tolist(), "final": final, "attack": attack is not None})
        device["last"] = {"risks": risks.tolist(), "final": final, "alarm": alarm, "guess": guess,
                          "reasons": self._reasons(device, record, errors)}
        incident = device["incident"]
        if incident is None and sum(device["recent"]) >= 2:
            recent = list(device["recent"])
            incident = {"id": len(self.incidents) + 1, "device": device["id"], "start": self.tick - (len(recent) - 1 - recent.index(True)),
                        "last": self.tick, "end": None, "alarms": sum(recent), "peak": final, "quiet": 0,
                        "hits": Counter(), "votes": Counter(), "truth": attack["kind"] if attack else None,
                        "by": attack["by"] if attack else None}
            self.incidents.append(incident)
            self.incidents = self.incidents[-200:]
            self.stats["true_incidents" if attack else "false_incidents"] += 1
            device["incident"] = incident
        elif incident is not None:
            incident["last"] = self.tick
            incident["peak"] = max(incident["peak"], final)
            incident["alarms"] += int(alarm)
            incident["quiet"] = 0 if alarm else incident["quiet"] + 1
            if attack and incident["truth"] is None:
                incident["truth"] = attack["kind"]
                incident["by"] = attack["by"]
                self.stats["true_incidents"] += 1
                self.stats["false_incidents"] -= 1
        if incident is not None and alarm:
            incident["hits"].update(k for k, r in zip(MODEL_KEYS, risks) if r >= 50)
            incident["votes"][guess or "unknown"] += 1
        if incident is not None and incident["quiet"] >= 3:
            incident["end"] = self.tick
            device["incident"] = None
            if self.on_close:
                self.on_close(self._closed_record(device, incident))
        if attack and not attack["detected"] and device["incident"] and alarm:
            attack["detected"] = True
            self.stats["detect_times"].append(self.tick - attack["start"] + 1)

    def _closed_record(self, device, incident):
        votes = incident["votes"].most_common(1)
        return {"device": device["name"], "ip": device["ip"], "device_type": device["type"],
                "start_tick": incident["start"], "end_tick": incident["end"],
                "duration": incident["end"] - incident["start"] + 1, "peak": round(incident["peak"], 1),
                "alarms": incident["alarms"], "hits_if": incident["hits"]["if"], "hits_ae": incident["hits"]["ae"],
                "hits_rf": incident["hits"]["rf"], "guess": votes[0][0] if votes else "unknown",
                "truth": incident["truth"], "launched_by": incident["by"]}

    def _reasons(self, device, record, errors):
        total = float(errors.sum()) or 1.0
        ranked = sorted(NUM_COLS, key=lambda c: errors[self.column_index[c]], reverse=True)[:3]
        normal = self.baseline.loc[device["type"]]
        return [{"feature": c, "share": errors[self.column_index[c]] / total,
                 "value": float(record[c]), "normal": float(normal[c])} for c in ranked]

    def kpis(self):
        s = self.stats
        return {
            "records": s["tp"] + s["fp"] + s["fn"] + s["tn"],
            "recall": s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else None,
            "fpr": s["fp"] / (s["fp"] + s["tn"]) if s["fp"] + s["tn"] else None,
            "mttd": float(np.mean(s["detect_times"])) if s["detect_times"] else None,
            "latency_ms": s["latency_ms"],
            "true_incidents": s["true_incidents"],
            "false_incidents": s["false_incidents"],
            "launched": s["launched"],
        }

    def snapshot(self, selected=0):
        self.catch_up()
        with self.lock:
            selected = min(max(0, selected), len(self.devices) - 1)
            cards = []
            for device in self.devices:
                last = device["last"]
                state = "incident" if device["incident"] else ("suspect" if last and last["alarm"] else "ok")
                cards.append({"id": device["id"], "name": device["name"], "ip": device["ip"], "type": device["type"],
                              "risk": last["final"] if last else 0.0, "state": state, "attack": device["attack"],
                              "spark": points([h["final"] for h in list(device["history"])[-30:]], SPARK_W, SPARK_H, 30)})
            focus = self.devices[selected]
            history = list(focus["history"])
            spans, run_start = [], None
            for i, h in enumerate(history + [{"attack": False}]):
                if h["attack"] and run_start is None:
                    run_start = i
                if not h["attack"] and run_start is not None:
                    spans.append({"x": (90 - len(history) + run_start) * CHART_W / 89, "w": (i - run_start) * CHART_W / 89})
                    run_start = None
            lines = {key: points([h["risks"][k] for h in history], CHART_W, CHART_H, 90) for k, key in enumerate(MODEL_KEYS)}
            lines["final"] = points([h["final"] for h in history], CHART_W, CHART_H, 90)
            incidents = []
            for incident in reversed(self.incidents[-10:]):
                end = incident["end"] or self.tick
                votes = incident["votes"].most_common(1)
                incidents.append(dict(incident, name=self.devices[incident["device"]]["name"], duration=end - incident["start"] + 1,
                                      guess=votes[0][0] if votes else "unknown", active=incident["end"] is None))
            return {
                "tick": self.tick,
                "clock": time.strftime("%H:%M:%S", time.gmtime(self.tick)),
                "settings": self.settings(),
                "kpis": self.kpis(),
                "cards": cards,
                "active": sum(1 for d in self.devices if d["incident"]),
                "focus": {"device": cards[selected], "last": focus["last"], "lines": lines, "spans": spans,
                          "threshold_y": CHART_H / 2, "width": CHART_W, "height": CHART_H},
                "incidents": incidents,
            }
