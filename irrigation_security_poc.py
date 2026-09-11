"""
Proof-of-Concept Implementation and Experimental Validation
(Section 8 companion code for "A Reference Architecture for Secure
Smart Irrigation")

This script simulates a small irrigation control chain:

    Field Sensor -> Gateway/Controller -> Actuator (valve/pump)
    External Weather Feed -> Decision Engine
    Dashboard/Operator -> Controller (override path)

Two controller implementations are provided:

  * NaiveController   - a "no architecture" baseline: accepts telemetry,
                         commands, feeds and overrides at face value.
  * SecureController  - implements the architecture proposed in the
                         paper: device authentication, anti-replay
                         (sequence + boot id + TTL freshness, per the
                         Accept(r) predicate in Section 6.3), local
                         safety authority (Section 6.1), feedback-aware
                         execution (Section 6.2), TTL/corroboration for
                         external feeds (B6), and MFA/dual-approval for
                         high-impact operator overrides (B3).

Six attack/failure scenarios from Table 6 are injected against both
controllers, and the outcome (succeeded / blocked) is recorded and
printed as a summary table, mirroring the "Evidence required for
pass/fail decision" column of the paper. A seventh, nominal-operation
scenario (no injected fault) is then run against both controllers to
check specificity: that legitimate, well-formed telemetry, commands,
overrides, feeds, and updates are still accepted/executed and not
incorrectly blocked.

This is a self-contained logical simulation (no real network, hardware,
or protocol traffic) intended to validate the *architectural* claims of
the paper -- it is not a penetration-testing tool and implements no
attack techniques beyond the abstract patterns (spoofing, replay,
staleness, token theft, unsigned updates) already named in the paper's
own threat model.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import platform
import sys
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple


# --------------------------------------------------------------------------
# Shared primitives
# --------------------------------------------------------------------------

def hmac_sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


DEVICE_KEYS: Dict[str, bytes] = {
    "sensor-023": b"soil-moisture-sensor-secret-key",
    "gateway-A": b"gateway-A-secret-key",
    "operator-dashboard": b"dashboard-service-secret-key",
    "weather-vendor": b"weather-vendor-secret-key",
}

UNKNOWN_KEY = b"attacker-does-not-have-the-real-key"


@dataclass
class TelemetryRecord:
    device_id: str
    location_zone: str
    observed_property: str
    value: float
    unit: str
    measurement_time: float          # epoch seconds, claimed by device
    gateway_receive_time: float      # epoch seconds, set by gateway on arrival
    boot_id: str
    seq: int
    ttl_seconds: float
    calibration_version: str
    firmware_version: str
    clock_source: str
    clock_uncertainty_ms: float
    signature: str = ""              # HMAC over canonical payload
    payload_digest: str = ""         # SHA-256 over canonical payload (integrity, not authenticity)
    quality_flag: str = "VALID"

    def canonical_payload(self) -> str:
        return (f"{self.device_id}|{self.location_zone}|{self.observed_property}|"
                f"{self.value}|{self.unit}|{self.measurement_time}|{self.boot_id}|"
                f"{self.seq}|{self.ttl_seconds}|{self.calibration_version}|"
                f"{self.firmware_version}|{self.clock_source}|{self.clock_uncertainty_ms}")

    def finalize(self, key: bytes) -> None:
        """Sign the record (authenticity) and compute its content digest
        (integrity), both over the same canonical payload. A forger without
        the device key can still compute a correct digest -- the digest
        alone proves the message wasn't corrupted in transit, not who sent
        it; only the signature proves origin."""
        payload = self.canonical_payload()
        self.signature = hmac_sign(key, payload)
        self.payload_digest = hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class Command:
    command_id: str
    action: str                      # e.g. "OPEN_VALVE", "STOP_VALVE"
    issued_time: float
    ttl_seconds: float
    seq: int
    issuer: str                      # e.g. "scheduler", "operator-dashboard"
    signature: str

    def canonical_payload(self) -> str:
        return f"{self.command_id}|{self.action}|{self.issued_time}|{self.boot_id if hasattr(self,'boot_id') else ''}|{self.seq}"


@dataclass
class WeatherFeed:
    source: str
    forecast: str
    issued_time: float
    ttl_seconds: float
    signature: str


@dataclass
class OperatorSession:
    token: str
    role: str
    mfa_verified: bool
    issuer_ip_known: bool


PROV_CONTEXT = {
    "prov": "http://www.w3.org/ns/prov#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "irri": "https://example.org/irrigation/provenance#",
    "device_id": "irri:deviceId",
    "location_zone": "irri:locationZone",
    "observed_property": "irri:observedProperty",
    "value": {"@id": "prov:value", "@type": "xsd:decimal"},
    "unit": "irri:unit",
    "measurement_time": {"@id": "prov:generatedAtTime", "@type": "xsd:dateTime"},
    "gateway_receive_time": {"@id": "irri:gatewayReceiveTime", "@type": "xsd:dateTime"},
    "boot_id": "irri:bootId",
    "sequence_number": {"@id": "irri:sequenceNumber", "@type": "xsd:nonNegativeInteger"},
    "calibration_version": "irri:calibrationVersion",
    "firmware_version": "irri:firmwareVersion",
    "quality_flag": "irri:qualityFlag",
    "ttl_seconds": {"@id": "irri:ttlSeconds", "@type": "xsd:positiveInteger"},
    "clock_source": "irri:clockSource",
    "clock_uncertainty_ms": {"@id": "irri:clockUncertaintyMilliseconds", "@type": "xsd:nonNegativeInteger"},
    "payload_digest": "irri:payloadDigest",
}


def build_provo_record(rec: "TelemetryRecord") -> dict:
    """Build the Section 6.3 PROV-O / JSON-LD provenance record for a
    telemetry observation that has PASSED the Accept(r) predicate.
    This is only ever called for ACCEPTED records: a rejected/spoofed
    record does not get a provenance entity minted for it, which is
    itself part of the audit evidence (absence of a provenance record
    for a given wire message indicates it was never accepted as a
    trustworthy observation). Carries all eleven elements named in
    Section 6.3: record identifier, device identity and zone, observed
    property/value/unit, measurement and gateway-receive timestamps,
    boot id and sequence number, calibration and firmware versions,
    quality flag, TTL, clock source and uncertainty, and payload digest,
    linked to its acquisition activity and originating agent."""
    obs_id = f"urn:telemetry:{rec.device_id}:{rec.boot_id}:{rec.seq}"
    activity_id = f"urn:activity:acquisition:{rec.device_id}:{rec.boot_id}:{rec.seq}"
    device_uri = f"urn:device:{rec.device_id}"

    def iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    graph = [
        {
            "@id": obs_id,
            "@type": ["prov:Entity", "irri:TelemetryObservation"],
            "device_id": rec.device_id,
            "location_zone": rec.location_zone,
            "observed_property": rec.observed_property,
            "value": rec.value,
            "unit": rec.unit,
            "measurement_time": iso(rec.measurement_time),
            "gateway_receive_time": iso(rec.gateway_receive_time),
            "boot_id": rec.boot_id,
            "sequence_number": rec.seq,
            "calibration_version": rec.calibration_version,
            "firmware_version": rec.firmware_version,
            "quality_flag": rec.quality_flag,
            "ttl_seconds": int(rec.ttl_seconds),
            "clock_source": rec.clock_source,
            "clock_uncertainty_ms": rec.clock_uncertainty_ms,
            "payload_digest": f"sha256:{rec.payload_digest}",
            "prov:wasGeneratedBy": {"@id": activity_id},
            "prov:wasAttributedTo": {"@id": device_uri},
        },
        {
            "@id": activity_id,
            "@type": ["prov:Activity", "irri:MeasurementAcquisition"],
            "prov:wasAssociatedWith": {"@id": device_uri},
            "prov:endedAtTime": {"@value": iso(rec.measurement_time), "@type": "xsd:dateTime"},
        },
        {
            "@id": device_uri,
            "@type": ["prov:Agent", "irri:SensorDevice"],
            "device_id": rec.device_id,
            "location_zone": rec.location_zone,
        },
    ]
    return {"@context": PROV_CONTEXT, "@graph": graph}


# --------------------------------------------------------------------------
# Physical process model (very small, deterministic)
# --------------------------------------------------------------------------

class Valve:
    """A toy hydraulic actuator with independent physical feedback."""

    def __init__(self):
        self.state = "CLOSED"
        self.flow_lpm = 0.0

    def open(self, attacker_blocks_feedback: bool = False):
        self.state = "OPEN"
        # Independent physical feedback: flow should rise unless the
        # attacker is specifically able to suppress/spoof the feedback
        # sensor too (Feedback timeout scenario).
        self.flow_lpm = 0.0 if attacker_blocks_feedback else 42.0

    def close(self):
        self.state = "CLOSED"
        self.flow_lpm = 0.0


# --------------------------------------------------------------------------
# Result bookkeeping
# --------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    scenario: str
    controller: str
    attack_succeeded: bool
    evidence: List[str] = field(default_factory=list)

    def verdict(self) -> str:
        if self.scenario == "nominal_operation":
            # Here "attack_succeeded" is repurposed to mean "legitimate
            # operation was wrongly blocked" -- there is no attack.
            return "FALSE POSITIVE: legitimate op blocked (unsafe)" if self.attack_succeeded \
                   else "ACCEPTED/EXECUTED as expected (correct)"
        # An "unsafe" outcome is an attack that succeeded.
        return "ATTACK SUCCEEDED (unsafe)" if self.attack_succeeded else "BLOCKED (safe)"


RESULTS: List[ScenarioResult] = []


def record(scenario: str, controller: str, succeeded: bool, evidence: List[str]):
    r = ScenarioResult(scenario, controller, succeeded, evidence)
    RESULTS.append(r)
    tag = "SUCCEEDED" if succeeded else "blocked"
    print(f"  [{controller:<9}] {scenario:<24} -> attack {tag}")
    for e in evidence:
        print(f"               evidence: {e}")


# --------------------------------------------------------------------------
# Naive controller (no architecture)
# --------------------------------------------------------------------------

class NaiveController:
    """Accepts telemetry, commands, overrides and feeds at face value.
    Represents a 'monitoring app' style irrigation system with no
    trust-boundary enforcement, i.e. the situation the paper argues
    against."""

    name = "naive"

    def __init__(self, valve: Valve):
        self.valve = valve
        self.last_irrigation_decision = "NONE"

    def ingest_telemetry(self, rec: TelemetryRecord) -> Tuple[bool, List[str]]:
        # No auth check, no freshness check, no replay check.
        if rec.value < 0.15:
            self.last_irrigation_decision = "IRRIGATE"
        else:
            self.last_irrigation_decision = "HOLD"
        return True, [f"value {rec.value} accepted unconditionally, decision={self.last_irrigation_decision}"]

    def execute_command(self, cmd: Command, attacker_blocks_feedback: bool = False) -> Tuple[bool, List[str]]:
        # No signature check, no TTL check, no replay/sequence check.
        if cmd.action == "OPEN_VALVE":
            self.valve.open(attacker_blocks_feedback=attacker_blocks_feedback)
        elif cmd.action == "STOP_VALVE":
            self.valve.close()
        # No feedback verification at all -- command is "successful"
        # purely because it was accepted.
        return True, [f"command {cmd.command_id} executed with no TTL/replay/feedback check, valve={self.valve.state}"]

    def apply_weather_feed(self, feed: WeatherFeed) -> Tuple[bool, List[str]]:
        # Used directly, regardless of age or source validation.
        applied = feed.forecast
        return True, [f"forecast '{applied}' applied directly with no freshness/corroboration check"]

    def apply_override(self, session: OperatorSession, action: str) -> Tuple[bool, List[str]]:
        # Any presented token is trusted.
        if action == "OPEN_VALVE":
            self.valve.open()
        return True, [f"override '{action}' executed on presented token alone (mfa_verified={session.mfa_verified})"]

    def install_update(self, signed: bool, signature_valid: bool, approved_rollout: bool) -> Tuple[bool, List[str]]:
        # Installs whatever is offered.
        return True, [f"firmware installed (signed={signed}, sig_valid={signature_valid}, approved_rollout={approved_rollout}) -- no verification performed"]


# --------------------------------------------------------------------------
# Secure controller (implements the paper's architecture)
# --------------------------------------------------------------------------

class SecureController:
    """Implements: device authentication, Accept(r) freshness/ordering
    predicate (Sec. 6.3), local safety authority (Sec. 6.1),
    feedback-aware execution (Sec. 6.2), B6 external-feed corroboration,
    and B3 MFA/dual-approval for high-impact overrides."""

    name = "secure"

    FRESHNESS_SLACK = 5.0        # seconds of allowed clock uncertainty
    FEEDBACK_WINDOW = 3.0        # seconds allowed for physical feedback
    MIN_EXPECTED_FLOW = 5.0      # lpm - below this, feedback is considered absent

    def __init__(self, valve: Valve):
        self.valve = valve
        self.last_seq_by_device: Dict[Tuple[str, str], int] = {}
        self.last_cmd_seq: int = -1
        self.seen_command_ids: set[str] = set()
        self.last_irrigation_decision = "NONE"
        self.safe_state = False
        self.provenance_log: List[dict] = []   # Section 6.3 PROV-O records, ACCEPTED only

    # ---- B1 / Section 6.3: telemetry Accept(r) predicate ----------------
    def _authenticated(self, rec: TelemetryRecord) -> bool:
        """Authenticated(r): proves origin. An attacker without the
        device's key cannot produce a valid HMAC, regardless of whether
        their forged payload is internally well-formed."""
        key = DEVICE_KEYS.get(rec.device_id)
        if key is None:
            return False
        expected = hmac_sign(key, rec.canonical_payload())
        return hmac.compare_digest(expected, rec.signature)

    def _integrity_valid(self, rec: TelemetryRecord) -> bool:
        """IntegrityValid(r): proves the payload matches its declared
        digest, i.e. was not corrupted/altered after the digest was
        computed. This is a distinct property from Authenticated(r):
        computing a correct digest requires no secret, so a forger can
        satisfy this check on their own forged payload just as easily as
        a legitimate sender can on a real one. It catches corruption in
        transit; only the signature check catches forgery of origin."""
        expected_digest = hashlib.sha256(rec.canonical_payload().encode()).hexdigest()
        return hmac.compare_digest(expected_digest, rec.payload_digest)

    def _fresh(self, rec: TelemetryRecord) -> bool:
        delta = rec.gateway_receive_time - rec.measurement_time
        return -self.FRESHNESS_SLACK <= delta <= rec.ttl_seconds + self.FRESHNESS_SLACK

    def _ordered(self, rec: TelemetryRecord) -> bool:
        k = (rec.device_id, rec.boot_id)
        last = self.last_seq_by_device.get(k, -1)
        return rec.seq > last

    def ingest_telemetry(self, rec: TelemetryRecord) -> Tuple[bool, List[str]]:
        ev = []
        auth_ok = self._authenticated(rec)
        ev.append(f"authenticated={auth_ok}")
        integrity_ok = self._integrity_valid(rec)
        ev.append(f"integrity_valid={integrity_ok}")
        fresh_ok = self._fresh(rec)
        ev.append(f"fresh={fresh_ok} (delta={rec.gateway_receive_time - rec.measurement_time:.1f}s, ttl={rec.ttl_seconds}s)")
        ordered_ok = self._ordered(rec)
        ev.append(f"ordered={ordered_ok} (seq={rec.seq}, last={self.last_seq_by_device.get((rec.device_id, rec.boot_id), -1)})")
        quality_ok = rec.quality_flag == "VALID"
        ev.append(f"quality_ok={quality_ok}")

        accept = auth_ok and integrity_ok and fresh_ok and ordered_ok and quality_ok
        if accept:
            self.last_seq_by_device[(rec.device_id, rec.boot_id)] = rec.seq
            self.last_irrigation_decision = "IRRIGATE" if rec.value < 0.15 else "HOLD"
            prov_record = build_provo_record(rec)
            self.provenance_log.append(prov_record)
            ev.append(f"record ACCEPTED, decision={self.last_irrigation_decision}")
            ev.append("Section 6.3 PROV-O provenance record MINTED for this observation "
                       f"(prov:Entity {prov_record['@graph'][0]['@id']})")
        else:
            ev.append("record REJECTED / marked SUSPECT; irrigation decision unchanged "
                       f"(remains {self.last_irrigation_decision})")
            ev.append("NO provenance record minted for this message -- its absence in the "
                       "provenance log is itself part of the audit evidence")
        return accept, ev

    # ---- B2/A2/A3, Section 6.1 + 6.2: command authorisation & feedback --
    def execute_command(self, cmd: Command, attacker_blocks_feedback: bool = False) -> Tuple[bool, List[str]]:
        ev = []
        key = DEVICE_KEYS.get(cmd.issuer)
        sig_ok = key is not None and hmac.compare_digest(hmac_sign(key, cmd.canonical_payload()), cmd.signature)
        ev.append(f"signature_valid={sig_ok}")

        age = time.time() - cmd.issued_time
        ttl_ok = age <= cmd.ttl_seconds
        ev.append(f"ttl_ok={ttl_ok} (age={age:.1f}s, ttl={cmd.ttl_seconds}s)")

        replay_ok = cmd.command_id not in self.seen_command_ids and cmd.seq > self.last_cmd_seq
        ev.append(f"replay_ok={replay_ok} (seq={cmd.seq}, last={self.last_cmd_seq})")

        authorised = sig_ok and ttl_ok and replay_ok
        if not authorised:
            ev.append("LOCAL SAFETY AUTHORITY: command REJECTED before actuation")
            return False, ev

        self.seen_command_ids.add(cmd.command_id)
        self.last_cmd_seq = cmd.seq

        # Local safety authority: only now does actuation happen.
        if cmd.action == "OPEN_VALVE":
            self.valve.open(attacker_blocks_feedback=attacker_blocks_feedback)
        elif cmd.action == "STOP_VALVE":
            self.valve.close()

        # Feedback-aware execution (Section 6.2): verify independent
        # physical feedback before treating the command as successful.
        if cmd.action == "OPEN_VALVE":
            feedback_ok = self.valve.flow_lpm >= self.MIN_EXPECTED_FLOW
            ev.append(f"feedback_check flow={self.valve.flow_lpm} lpm, expected>={self.MIN_EXPECTED_FLOW}")
            if not feedback_ok:
                self.valve.close()
                self.safe_state = True
                ev.append("command-feedback ASYMMETRY detected -> alarm raised, "
                           "valve forced to bounded safe state (CLOSED)")
                return False, ev

        ev.append(f"command executed and feedback-verified, valve={self.valve.state}")
        return True, ev

    # ---- B6: third-party / external feed --------------------------------
    def apply_weather_feed(self, feed: WeatherFeed) -> Tuple[bool, List[str]]:
        ev = []
        key = DEVICE_KEYS.get(feed.source)
        sig_ok = key is not None and hmac.compare_digest(hmac_sign(key, f"{feed.source}|{feed.forecast}|{feed.issued_time}"), feed.signature)
        ev.append(f"provenance_ok={sig_ok}")
        age = time.time() - feed.issued_time
        fresh_ok = age <= feed.ttl_seconds
        ev.append(f"fresh={fresh_ok} (age={age:.1f}s, ttl={feed.ttl_seconds}s)")

        if sig_ok and fresh_ok:
            ev.append(f"feed accepted, forecast '{feed.forecast}' applied to schedule")
            return True, ev
        else:
            ev.append("feed marked STALE/unverified -> requires local sensor corroboration "
                       "or human approval; irrigation plan NOT changed automatically")
            return False, ev

    # ---- B3: platform-application boundary / operator override ----------
    def apply_override(self, session: OperatorSession, action: str) -> Tuple[bool, List[str]]:
        ev = []
        ev.append(f"mfa_verified={session.mfa_verified}, issuer_ip_known={session.issuer_ip_known}, role={session.role}")
        # High-impact action (valve open) requires MFA + a recognised
        # session context; a bare stolen token is not sufficient.
        authorised = session.mfa_verified and session.issuer_ip_known and session.role == "operator"
        if not authorised:
            ev.append("high-impact override BLOCKED: additional MFA / context-bound approval required")
            return False, ev
        if action == "OPEN_VALVE":
            self.valve.open()
        ev.append(f"override authorised and executed, valve={self.valve.state}")
        return True, ev

    # ---- Management plane: firmware/update governance --------------------
    def install_update(self, signed: bool, signature_valid: bool, approved_rollout: bool) -> Tuple[bool, List[str]]:
        ev = [f"signed={signed}", f"signature_valid={signature_valid}", f"approved_rollout={approved_rollout}"]
        if signed and signature_valid and approved_rollout:
            ev.append("update installed")
            return True, ev
        ev.append("update REJECTED / rolled back; failure logged and alert raised")
        return False, ev


# --------------------------------------------------------------------------
# Attack scenarios (mirrors Table 6)
# --------------------------------------------------------------------------

def scenario_spoofed_telemetry():
    print("\n[1] Spoofed telemetry (B1, A1)")
    legit_prov_example = None
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        now = time.time()

        # First, a legitimate, correctly-signed reading arrives (this is
        # what normal operation looks like, and -- for the secure
        # controller -- is what mints a Section 6.3 provenance record).
        legit_key = DEVICE_KEYS["sensor-023"]
        legit = TelemetryRecord(
            device_id="sensor-023", location_zone="field-A", observed_property="soil-moisture",
            value=0.31, unit="m3/m3",
            measurement_time=now, gateway_receive_time=now,
            boot_id="boot-6f2c8f20", seq=4821, ttl_seconds=300,
            calibration_version="v2.1", firmware_version="1.4.2",
            clock_source="GNSS", clock_uncertainty_ms=10.0,
        )
        legit.finalize(legit_key)
        ctrl.ingest_telemetry(legit)
        if isinstance(ctrl, SecureController) and ctrl.provenance_log:
            legit_prov_example = ctrl.provenance_log[-1]

        # Then, an attacker with no device key injects a forged, low
        # soil-moisture reading with a higher sequence number, trying to
        # force an irrigation decision. The attacker can still compute a
        # correct payload digest for their own forged payload -- integrity
        # is a property of the bytes, not of who sent them -- but cannot
        # produce a valid signature without the real device key.
        fake = TelemetryRecord(
            device_id="sensor-023",
            location_zone="field-A", observed_property="soil-moisture",
            value=0.05,             # artificially low -> would trigger irrigation
            unit="m3/m3",
            measurement_time=now + 1,
            gateway_receive_time=now + 1,
            boot_id="attacker-boot",
            seq=1,
            ttl_seconds=300,
            calibration_version="unknown", firmware_version="unknown",
            clock_source="UNSYNCHRONISED", clock_uncertainty_ms=999.0,
        )
        fake.payload_digest = hashlib.sha256(fake.canonical_payload().encode()).hexdigest()
        fake.signature = hmac_sign(UNKNOWN_KEY, "irrelevant")  # wrong key
        accepted, ev = ctrl.ingest_telemetry(fake)
        # "Attack succeeds" if the forged low-moisture reading is used
        # to drive an irrigation decision.
        attack_succeeded = accepted and ctrl.last_irrigation_decision == "IRRIGATE"
        record("spoofed_telemetry", ctrl.name, attack_succeeded, ev)

    if legit_prov_example is not None:
        print("\n  Example Section 6.3 PROV-O record minted for the ACCEPTED reading:")
        print("  " + json.dumps(legit_prov_example, indent=2).replace("\n", "\n  "))
    return legit_prov_example


def scenario_command_replay():
    print("\n[2] Command replay (B2/B4, A2/A3)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        key = DEVICE_KEYS["operator-dashboard"]
        cmd_id = str(uuid.uuid4())
        old_time = time.time() - 600  # issued 10 minutes ago
        original = Command(
            command_id=cmd_id, action="OPEN_VALVE", issued_time=old_time,
            ttl_seconds=30, seq=10, issuer="operator-dashboard", signature="",
        )
        original.signature = hmac_sign(key, original.canonical_payload())
        # Attacker captured this old, expired command and replays it now.
        valve2 = Valve()
        ctrl2 = ctrl  # same controller instance
        ok, ev = ctrl2.execute_command(original)
        attack_succeeded = ok and ctrl2.valve.state == "OPEN"
        record("command_replay", ctrl.name, attack_succeeded, ev)


def scenario_feedback_timeout():
    print("\n[3] Feedback timeout / blocked physical feedback (Sec 6.2)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        key = DEVICE_KEYS["operator-dashboard"]
        cmd = Command(
            command_id=str(uuid.uuid4()), action="OPEN_VALVE",
            issued_time=time.time(), ttl_seconds=30, seq=1,
            issuer="operator-dashboard", signature="",
        )
        cmd.signature = hmac_sign(key, cmd.canonical_payload())
        # Attacker blocks/suppresses the flow sensor so the valve
        # reports OPEN in software but no water is actually moving
        # (or, conversely, a legitimate-looking command is sent while
        # the physical process does not respond).
        ok, ev = ctrl.execute_command(cmd, attacker_blocks_feedback=True)
        # "Attack succeeds" if the controller believes the command
        # succeeded despite the absence of real physical feedback.
        attack_succeeded = ok and ctrl.valve.state == "OPEN"
        record("feedback_timeout", ctrl.name, attack_succeeded, ev)


def scenario_compromised_session():
    print("\n[4] Compromised operator session / stolen dashboard token (B3, A5)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        stolen_session = OperatorSession(
            token="stolen-jwt-abc123",
            role="operator",
            mfa_verified=False,     # attacker has the token but not the MFA factor
            issuer_ip_known=False,  # request comes from an unrecognised location
        )
        ok, ev = ctrl.apply_override(stolen_session, "OPEN_VALVE")
        attack_succeeded = ok and ctrl.valve.state == "OPEN"
        record("compromised_session", ctrl.name, attack_succeeded, ev)


def scenario_stale_weather_feed():
    print("\n[5] Stale external weather feed (B6, A4)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        old_feed = WeatherFeed(
            source="weather-vendor",
            forecast="HEAVY_RAIN_EXPECTED",  # would suppress irrigation if trusted
            issued_time=time.time() - 3 * 3600,  # 3 hours old
            ttl_seconds=1800,  # 30-minute freshness limit
            signature=hmac_sign(DEVICE_KEYS["weather-vendor"], "irrelevant-because-key-mismatch-not-tested-here"),
        )
        # (signature deliberately mismatched below to also show provenance failure)
        old_feed.signature = hmac_sign(DEVICE_KEYS["weather-vendor"], f"weather-vendor|{old_feed.forecast}|{old_feed.issued_time}")
        applied, ev = ctrl.apply_weather_feed(old_feed)
        attack_succeeded = applied  # stale data directly changed the plan
        record("stale_weather_feed", ctrl.name, attack_succeeded, ev)


def scenario_unsafe_update():
    print("\n[6] Unsafe / unsigned firmware update (Management plane)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        # Attacker offers an unsigned firmware image outside the
        # approved rollout policy.
        installed, ev = ctrl.install_update(signed=False, signature_valid=False, approved_rollout=False)
        attack_succeeded = installed
        record("unsafe_update", ctrl.name, attack_succeeded, ev)


def scenario_nominal_operation():
    """Specificity check (Table 6, row 7): no attack is injected here.
    Every telemetry record, command, override, feed, and update below is
    well-formed and legitimate (correct signature, within TTL/freshness,
    next-in-sequence, MFA-verified, approved rollout). A correctly
    implemented architecture should accept/execute all five without
    modification; the six preceding scenarios show the architecture
    catches bad input (sensitivity), and this scenario shows it does not
    also reject good input (specificity) -- i.e. the secure controller is
    not simply rejecting everything unconditionally."""
    print("\n[7] Nominal operation, no injected fault (specificity check)")
    for ctrl_cls in (NaiveController, SecureController):
        valve = Valve()
        ctrl = ctrl_cls(valve)
        now = time.time()
        ev_all: List[str] = []

        # 7a. Legitimate telemetry: correctly signed, fresh, in-order, VALID.
        tel_key = DEVICE_KEYS["sensor-023"]
        rec = TelemetryRecord(
            device_id="sensor-023", location_zone="field-A", observed_property="soil-moisture",
            value=0.31, unit="m3/m3",
            measurement_time=now, gateway_receive_time=now,
            boot_id="boot-nominal-01", seq=1, ttl_seconds=300,
            calibration_version="v2.1", firmware_version="1.4.2",
            clock_source="GNSS", clock_uncertainty_ms=10.0,
        )
        rec.finalize(tel_key)
        telemetry_accepted, ev_tel = ctrl.ingest_telemetry(rec)
        ev_all += ["-- 7a. legitimate telemetry --"] + ev_tel

        # 7b. Legitimate command: correctly signed, within TTL, next seq,
        # normal physical conditions (feedback confirms flow).
        cmd_key = DEVICE_KEYS["operator-dashboard"]
        cmd = Command(
            command_id=str(uuid.uuid4()), action="OPEN_VALVE",
            issued_time=time.time(), ttl_seconds=30, seq=1,
            issuer="operator-dashboard", signature="",
        )
        cmd.signature = hmac_sign(cmd_key, cmd.canonical_payload())
        command_executed, ev_cmd = ctrl.execute_command(cmd)  # feedback NOT blocked
        ev_all += ["-- 7b. legitimate command --"] + ev_cmd

        # 7c. Legitimate operator override: MFA-verified, known context.
        good_session = OperatorSession(
            token="valid-session-token-xyz", role="operator",
            mfa_verified=True, issuer_ip_known=True,
        )
        override_executed, ev_ovr = ctrl.apply_override(good_session, "OPEN_VALVE")
        ev_all += ["-- 7c. legitimate operator override --"] + ev_ovr

        # 7d. Fresh, correctly-signed weather feed.
        feed_key = DEVICE_KEYS["weather-vendor"]
        good_feed = WeatherFeed(
            source="weather-vendor", forecast="CLEAR",
            issued_time=time.time(), ttl_seconds=1800, signature="",
        )
        good_feed.signature = hmac_sign(feed_key, f"weather-vendor|{good_feed.forecast}|{good_feed.issued_time}")
        feed_applied, ev_feed = ctrl.apply_weather_feed(good_feed)
        ev_all += ["-- 7d. legitimate weather feed --"] + ev_feed

        # 7e. Properly signed, approved-rollout firmware update.
        update_installed, ev_upd = ctrl.install_update(signed=True, signature_valid=True, approved_rollout=True)
        ev_all += ["-- 7e. legitimate firmware update --"] + ev_upd

        # "Unsafe" here means the controller incorrectly BLOCKED legitimate
        # operation (a false positive / availability failure), not that an
        # attack succeeded -- no attack was attempted in this scenario.
        blocked_legitimate = not (telemetry_accepted and command_executed
                                   and override_executed and feed_applied and update_installed)
        record("nominal_operation", ctrl.name, blocked_legitimate, ev_all)


# --------------------------------------------------------------------------
# Runner + summary
# --------------------------------------------------------------------------

def script_sha256() -> str:
    """SHA-256 of this script's own source, so a reader can confirm the
    code they are running/reviewing is byte-identical to what is cited
    in the paper, independent of trusting any printed output."""
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_all():
    print("=" * 78)
    print("Section 8 Proof-of-Concept: Naive vs. Secure Irrigation Architecture")
    print("=" * 78)
    print(f"script_sha256   = {script_sha256()}")
    print(f"python_version  = {platform.python_version()}")
    print(f"platform        = {platform.platform()}")
    run_started = datetime.now(timezone.utc).isoformat()
    print(f"run_started_utc = {run_started}")

    legit_prov_example = scenario_spoofed_telemetry()
    scenario_command_replay()
    scenario_feedback_timeout()
    scenario_compromised_session()
    scenario_stale_weather_feed()
    scenario_unsafe_update()
    scenario_nominal_operation()

    print("\n" + "=" * 78)
    print("SUMMARY (Table 6 style pass/fail matrix)")
    print("=" * 78)
    header = f"{'Scenario':<24}{'Naive controller':<28}{'Secure controller':<28}"
    print(header)
    print("-" * len(header))

    by_scenario: Dict[str, Dict[str, ScenarioResult]] = {}
    for r in RESULTS:
        by_scenario.setdefault(r.scenario, {})[r.controller] = r

    ATTACK_SCENARIOS = ["spoofed_telemetry", "command_replay", "feedback_timeout",
                        "compromised_session", "stale_weather_feed", "unsafe_update"]
    NOMINAL_SCENARIO = "nominal_operation"

    naive_unsafe = 0
    secure_unsafe = 0
    for scenario in ATTACK_SCENARIOS:
        res = by_scenario[scenario]
        n = res["naive"].verdict()
        s = res["secure"].verdict()
        if res["naive"].attack_succeeded:
            naive_unsafe += 1
        if res["secure"].attack_succeeded:
            secure_unsafe += 1
        print(f"{scenario:<24}{n:<28}{s:<28}")

    naive_false_positive = by_scenario[NOMINAL_SCENARIO]["naive"].attack_succeeded
    secure_false_positive = by_scenario[NOMINAL_SCENARIO]["secure"].attack_succeeded
    n7 = by_scenario[NOMINAL_SCENARIO]["naive"].verdict()
    s7 = by_scenario[NOMINAL_SCENARIO]["secure"].verdict()
    print(f"{NOMINAL_SCENARIO:<24}{n7:<28}{s7:<28}")

    print("-" * len(header))
    print(f"Sensitivity (6 attack scenarios) -> unsafe outcomes: "
          f"naive {naive_unsafe}/{len(ATTACK_SCENARIOS)}   secure {secure_unsafe}/{len(ATTACK_SCENARIOS)}")
    print(f"Specificity (1 nominal scenario) -> false positives: "
          f"naive {int(naive_false_positive)}/1   secure {int(secure_false_positive)}/1")
    print("\nInterpretation: the naive controller (no trust-boundary enforcement)")
    print("is compromised or driven into an unsafe state by every injected")
    print("scenario. The secure controller, implementing the paper's local")
    print("safety authority, Accept(r) freshness/ordering predicate, feedback-")
    print("aware execution, and B3/B6 corroboration requirements, blocks or")
    print("bounds every attack scenario (sensitivity), matching the 'Expected")
    print("architectural response' column of Table 6, while still accepting")
    print("and executing every legitimate operation in the nominal scenario")
    print("(specificity) -- i.e. it is discriminating rather than simply")
    print("rejecting all input unconditionally.")

    # ---- Machine-readable, independently re-checkable export ----------
    export = {
        "script_sha256": script_sha256(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "run_started_utc": run_started,
        "run_finished_utc": datetime.now(timezone.utc).isoformat(),
        "scenarios": [
            {
                "scenario": r.scenario,
                "controller": r.controller,
                "attack_succeeded": r.attack_succeeded,
                "verdict": r.verdict(),
                "evidence": r.evidence,
            }
            for r in RESULTS
        ],
        "summary": {
            "total_attack_scenarios": len(ATTACK_SCENARIOS),
            "naive_unsafe_count": naive_unsafe,
            "secure_unsafe_count": secure_unsafe,
            "total_nominal_scenarios": 1,
            "naive_false_positive_count": int(naive_false_positive),
            "secure_false_positive_count": int(secure_false_positive),
        },
        "example_provo_record_section_6_3": legit_prov_example,
    }
    out_path = "poc_results.json"
    with open(out_path, "w") as f:
        json.dump(export, f, indent=2)
    print(f"\nMachine-readable results written to: {out_path}")

    # ---- Hard, falsifiable checks -------------------------------------
    # These assertions make the claimed outcome ("naive: 6/6 unsafe,
    # secure: 0/6 unsafe, and secure has 0 false positives on nominal
    # operation") a property that is checked by the program itself, not
    # merely asserted in prose. A non-zero exit code means the claimed
    # result was NOT reproduced on this run/environment.
    assert len(by_scenario) == 7, "expected 6 attack scenarios + 1 nominal scenario"
    assert naive_unsafe == 6, f"expected naive controller unsafe on all 6 attack scenarios, got {naive_unsafe}"
    assert secure_unsafe == 0, f"expected secure controller unsafe on 0 attack scenarios, got {secure_unsafe}"
    assert secure_false_positive == False, "expected secure controller to accept/execute all legitimate nominal-scenario operations"
    print("\nAll assertions passed: naive=6/6 unsafe, secure=0/6 unsafe on attack")
    print("scenarios, and secure=0/1 false positives on the nominal scenario")
    print("(exit code 0 confirms this run reproduced the claimed result).")

    return export


if __name__ == "__main__":
    run_all()
