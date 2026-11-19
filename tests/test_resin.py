# tests/test_resin.py
"""Resin printers: the Anycubic Photon P1 (modelId 131, /info deviceType "lcd").

Every payload here is a capture from a real P1 on firmware 5.0.6.7, or from Photon Workshop
4.2.1's own MQTT log on the same network, with the device id and serial replaced. What the P1
does differently from the Kobras, all of it confirmed on that printer:

- /ctrl names the broker as a bare "host:port", where a Kobra gives "mqtts://host:port".
- Its broker accepts only the client id /ctrl names ("clientId"); a random one is refused.
- It refuses `.../#` subscriptions and grants `printer/+/<model>/<device>/+/report`.
- It answers requests on `pc/printer/...` with `data` an empty object, never null.
- There is no `info` report: `status` says free or busy (data null) and `print` carries the
  job's phase in its envelope `state`, with the same progress keys a Kobra uses.
"""
import base64
import json
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.anycubic.anycubic_local import handshake, mqtt as m
from custom_components.anycubic.anycubic_local.const import (
    RESIN_CONNECT_QUERY_TYPES,
    RESIN_QUERY_TYPES,
    query_topic,
    report_subscription,
)
from custom_components.anycubic.anycubic_local.handshake import HandshakeResult
from custom_components.anycubic.anycubic_local.models import (
    PrinterState,
    apply_resin_print,
    apply_resin_status,
)
from custom_components.anycubic.const import DOMAIN, MODEL_NAMES
from custom_components.anycubic.coordinator import AnycubicCoordinator

PREFIX = "anycubic/anycubicCloud/v1"
HS = HandshakeResult("1.2.3.4", 8883, "clientUser1", "admin", "DEV", "131", "SER-P1",
                     model_name="Anycubic Photon P1", device_type="lcd", client_id="clientId")


# ---------------------------------------------------------------- captured P1 traffic
STATUS_FREE = {"type": "status", "action": "workReport", "msgid": "a0e12d64",
               "state": "free", "timestamp": 1795058020870, "code": 200, "msg": "",
               "data": None}
STATUS_BUSY = {**STATUS_FREE, "state": "busy"}
LAN_INFO = {"type": "lanInfo", "action": "query", "msgid": "6533a971", "state": "done",
            "timestamp": 1795058021371, "code": 200, "msg": "",
            "data": {"printerName": "", "version": "5.0.6.7"}}
LIGHT = {"type": "light", "action": "query", "msgid": "10e2b650", "state": "done",
         "code": 200, "timestamp": 1795058021873,
         "data": {"lights": [{"type": 3, "status": 0}]}}
# The pre-print checks, pushed as the job is sent. No progress keys.
PRINT_MONITORING = {
    "type": "print", "action": "autoOperation", "msgid": "dd7daf26", "state": "monitoring",
    "timestamp": 1795052056807, "code": 0, "msg": "",
    "data": {"checkStatus": [{"name": "FileVerification", "status": 0},
                             {"name": "resinHeat", "status": -2}], "taskid": "0"}}
# The start, while the resin is preheated. Trimmed of source_info, settings and settings_adv.
PRINT_PREHEATING = {
    "type": "print", "action": "start", "msgid": "4b9dd194", "state": "preheating",
    "timestamp": 1795052152286, "code": 200, "msg": "",
    "data": {"taskid": "", "task_mode": 1, "dual_platform_mode_enable": 0,
             "heating_remain_time": -1, "heating_skip_allowed": True,
             "localtask": "bebb802d-144e-4dc6-bf3b-23877cb5fe1a",
             "filename": "01_AmeraLabs_calibration_part_town_raft.pp1", "remain_time": 45,
             "model_hight": 15.2, "curr_layer": 0, "compensation_layers": "cp0",
             "total_layers": 304, "supplies_usage": 1.985313, "tensile_value": -4375,
             "progress": 0, "z_thick": 0.05, "anti_count": 16, "print_time": 0,
             "slicer": "AC-PC"}}
AUTO_OPERATION = {
    "type": "autoOperation", "action": "reportStatus", "msgid": "26e23092", "state": "done",
    "timestamp": 1795058022872, "code": 200, "msg": "",
    "data": {"currentStatus": [{"name": "resinHeat", "support": 1, "editable": 1, "status": 1},
                               {"name": "smartSpeed", "support": 0, "editable": 1,
                                "status": 1}]}}


def _envelope(report):
    """What the transport hands the coordinator for a resin report (see mqtt._handle)."""
    return {key: report.get(key) for key in ("action", "state", "code", "msg", "data")}


# ------------------------------------------------------------------------- handshake
def _enc(plaintext: bytes, token: str, local_token: str) -> str:
    key = token[16:32].encode(); iv = local_token.encode()[:16].ljust(16, b"\0")
    p = PKCS7(128).padder(); padded = p.update(plaintext) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(e.update(padded) + e.finalize()).decode()


def test_the_p1_handshake_with_a_bare_broker_address():
    """The P1's /ctrl answer, which used to fail at the decrypt step as "not a printer's"."""
    token = "0123456789abcdefABCDEF0123456789"; local_token = "localtok12345678"
    info = {"cn": "SER-P1", "code": 0, "ctrlInfoUrl": "http://1.2.3.4:18910/ctrl",
            "ctrlType": "lan", "deviceName": "Anycubic Photon P1", "deviceType": "lcd",
            "env": "prod", "ip": "1.2.3.4", "message": "OK", "modelId": "131",
            "modelName": "Anycubic Photon P1", "token": token, "zone": "cn"}
    decrypted = {"deviceType": "lcd", "accountDeleteUrl": "accountDeleteUrl",
                 "broker": "1.2.3.4:8883", "clientId": "clientId", "deviceId": "DEV",
                 "username": "clientUser1", "password": "admin", "cacrt": "-----BEGIN…",
                 "modeId": "131", "modelName": "Anycubic Photon P1", "ip": "1.2.3.4",
                 "mac": "AA:BB:CC:DD:EE:FF", "fileUploadUrl": "http://1.2.3.4:18910/upload/",
                 "rtsp": ""}
    ctrl = {"code": 200, "message": "success", "data": {
        "token": local_token, "info": _enc(json.dumps(decrypted).encode(), token, local_token)}}

    res = handshake.do_handshake(
        "1.2.3.4", fetch=lambda method, url: info if url.endswith("/info") else ctrl)

    assert (res.broker_host, res.broker_port) == ("1.2.3.4", 8883)
    assert (res.username, res.device_id, res.model_id) == ("clientUser1", "DEV", "131")
    assert res.client_id == "clientId"
    assert res.device_type == "lcd" and res.resin


def test_a_kobra_is_not_resin_and_keeps_its_own_client_id():
    kobra = HandshakeResult("1.2.3.4", 9883, "u", "p", "DEV", "20029", "SER",
                            device_type="fdm", client_id="clientId")
    assert not kobra.resin
    assert m._client_id(kobra).startswith("ha-")
    assert m._client_id(HS) == "clientId"


def test_the_p1_has_a_name():
    assert MODEL_NAMES["131"] == "Anycubic Photon P1"


# ------------------------------------------------------------------------- transport
class FakeClient:
    def __init__(self, *a, client_id=None, **k):
        self.client_id = client_id; self.subs = []; self.pubs = []
        self.on_message = None; self.on_connect = None; self.on_disconnect = None
    def username_pw_set(self, u, p): self.u, self.p = u, p
    def tls_set(self, **k): pass
    def tls_insecure_set(self, v): pass
    def connect(self, h, port, keepalive=60):
        self.conn = (h, port)
        if self.on_connect:
            self.on_connect(self, None, {}, 0)
    def loop_start(self): pass
    def loop_stop(self): pass
    def disconnect(self): pass
    def subscribe(self, t): self.subs.append(t)
    def publish(self, t, payload):
        self.pubs.append((t, json.loads(payload)))
        return type("Info", (), {"rc": 0})()


def _deliver(client, report):
    class Msg:
        topic = f"{PREFIX}/printer/public/131/DEV/{report['type']}/report"
        payload = json.dumps(report).encode()
    client._c.on_message(client._c, None, Msg())


def test_the_transport_connects_as_photon_workshop_does():
    client = m.AnycubicMqtt(HS, on_report=lambda t, d: None, client_factory=FakeClient)
    client.connect()
    assert client._c.client_id == "clientId"
    assert (client._c.u, client._c.p) == ("clientUser1", "admin")
    # The one filter the P1's broker grants. `.../#` is refused.
    assert client._c.subs == [f"{PREFIX}/printer/+/131/DEV/+/report"]


def test_resin_requests_go_to_pc_printer_with_an_empty_data_object():
    client = m.AnycubicMqtt(HS, on_report=lambda t, d: None, client_factory=FakeClient)
    client.connect()
    client.query("status")
    client.query("autoOperation")
    (t1, status), (t2, auto) = client._c.pubs
    assert t1 == f"{PREFIX}/pc/printer/131/DEV/status"
    assert status["action"] == "query" and status["data"] == {} and status["type"] == "status"
    assert t2 == f"{PREFIX}/pc/printer/131/DEV/autoOperation"
    assert auto["action"] == "getStatus" and auto["data"] == {}


def test_a_resin_report_is_handed_on_with_its_envelope():
    """`status` has data null and the phase is the envelope's `state`: both must get through."""
    seen = []
    client = m.AnycubicMqtt(HS, on_report=lambda t, d: seen.append((t, d)),
                            client_factory=FakeClient)
    client.connect()
    _deliver(client, STATUS_BUSY)
    _deliver(client, PRINT_PREHEATING)
    assert seen[0] == ("status", _envelope(STATUS_BUSY))
    assert seen[1][0] == "print" and seen[1][1]["state"] == "preheating"
    assert seen[1][1]["data"]["total_layers"] == 304


def test_kobra_topics_are_unchanged():
    assert query_topic("20029", "DEV", "info") == f"{PREFIX}/web/printer/20029/DEV/info"
    assert report_subscription("20029", "DEV") == f"{PREFIX}/printer/public/20029/DEV/#"


# -------------------------------------------------------------------------- parsing
def test_a_preheating_report_gives_the_job_and_its_progress():
    state = PrinterState()
    assert apply_resin_print(state, _envelope(PRINT_PREHEATING))
    assert state.status == "preheating" and state.raw_state == "busy"
    assert not state.printing and not state.paused
    assert (state.current_layer, state.total_layers, state.progress) == (0, 304, 0)
    assert state.filename == "01_AmeraLabs_calibration_part_town_raft.pp1"
    assert state.remain_time == 45 and state.print_time == 0
    assert state.filament_used == 1.985313      # millilitres of resin on a resin printer
    assert state.layer_height == 0.05 and state.model_height == 15.2
    assert state.preheat_remaining is None      # -1 is "not known"


def test_the_pre_print_checks_are_a_phase_with_no_progress():
    state = PrinterState()
    assert apply_resin_print(state, _envelope(PRINT_MONITORING))
    assert state.status == "monitoring" and state.progress is None


def test_a_late_check_report_does_not_take_the_job_back_to_monitoring():
    """Seen live on a P1: monitoring, preheating, then monitoring again in the same second."""
    state = PrinterState()
    apply_resin_print(state, _envelope(PRINT_MONITORING))
    apply_resin_print(state, _envelope(PRINT_PREHEATING))
    assert not apply_resin_print(state, _envelope(PRINT_MONITORING))
    assert state.status == "preheating"
    # A new job's checks, after the last one ended, are its phase again.
    apply_resin_status(state, STATUS_FREE)
    apply_resin_print(state, _envelope(PRINT_MONITORING))
    assert state.status == "monitoring"


def test_printing_and_paused_follow_the_phase():
    state = PrinterState()
    apply_resin_print(state, {"state": "printing", "data": {"progress": 40, "curr_layer": 120}})
    assert state.printing and not state.paused and state.current_layer == 120
    apply_resin_print(state, {"state": "paused", "data": None})
    assert state.paused and not state.printing and state.current_layer == 120


# ----------------------------------------------------------------------- coordinator
class FakeTransport:
    def __init__(self, hs, on_report, **k):
        self.on_report = on_report; self.queries = []; self.connected = False
    def connect(self): self.connected = True
    def disconnect(self): self.connected = False
    def query(self, t): self.queries.append(t)
    def publish(self, topic, payload): pass


async def _coordinator(hass):
    coord = AnycubicCoordinator(hass, HS, transport_factory=FakeTransport)
    await coord.async_start()
    return coord


def _report(coord, report):
    coord._on_report(report["type"], _envelope(report))


async def test_the_coordinator_asks_a_resin_printer_its_own_questions(hass):
    coord = await _coordinator(hass)
    assert coord._transport.queries == [*RESIN_QUERY_TYPES, *RESIN_CONNECT_QUERY_TYPES]
    assert "info" not in coord._transport.queries
    assert "peripherie" not in coord._transport.queries
    coord._transport.queries.clear()
    await coord._async_update_data()
    assert coord._transport.queries == list(RESIN_QUERY_TYPES)


async def test_a_resin_job_from_start_to_finish(hass):
    coord = await _coordinator(hass)
    events = []
    coord.async_add_event_listener(lambda event, attrs: events.append(event))
    printer = coord.data.printer

    _report(coord, STATUS_FREE)
    _report(coord, LAN_INFO)
    await hass.async_block_till_done()
    assert printer.status == "idle" and printer.firmware == "5.0.6.7"

    _report(coord, PRINT_MONITORING)
    _report(coord, STATUS_BUSY)          # busy says less than the phase: the phase stays
    _report(coord, PRINT_PREHEATING)
    _report(coord, PRINT_MONITORING)     # a late check report, as the P1 sends one
    await hass.async_block_till_done()
    assert printer.status == "preheating" and printer.total_layers == 304
    assert events == ["started"]

    coord._on_report("print", {"state": "printing", "data": {"progress": 50, "curr_layer": 152}})
    await hass.async_block_till_done()
    assert printer.printing and printer.progress == 50

    _report(coord, STATUS_FREE)
    await hass.async_block_till_done()
    assert printer.status == "idle" and not printer.printing
    assert events == ["started", "finished"]


async def test_a_job_already_running_shows_as_busy_until_its_phase_arrives(hass):
    coord = await _coordinator(hass)
    _report(coord, STATUS_BUSY)
    await hass.async_block_till_done()
    assert coord.data.printer.status == "busy"


async def test_feature_switches_and_the_lamp_are_kept_for_diagnostics(hass):
    coord = await _coordinator(hass)
    _report(coord, AUTO_OPERATION)
    _report(coord, LIGHT)
    await hass.async_block_till_done()
    assert coord.raw_features == AUTO_OPERATION["data"]
    assert coord.data.camera_light is not None and coord.data.camera_light.on is False


# -------------------------------------------------------------------------- entities
async def test_a_photon_p1_gets_resin_entities_and_no_kobra_hardware(hass):
    entry = MockConfigEntry(domain=DOMAIN, unique_id="SER-P1", data={"host": "1.2.3.4"})
    entry.add_to_hass(hass)
    with patch("custom_components.anycubic.do_handshake", return_value=HS), \
         patch("custom_components.anycubic.coordinator.mqtt_mod.AnycubicMqtt", FakeTransport):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    names = {state.entity_id for state in hass.states.async_all()}
    p1 = "anycubic_photon_p1"
    for sensor in ("status", "progress", "current_layer", "total_layers", "time_remaining",
                   "elapsed_time", "file_name", "firmware", "resin_used", "layer_height",
                   "model_height", "pause_reason"):
        assert f"sensor.{p1}_{sensor}" in names, sensor
    assert f"binary_sensor.{p1}_printing" in names
    assert f"event.{p1}_print_event" in names
    # Nothing a resin printer does not have, and no commands nobody has captured from one.
    unexpected = {n for n in names if p1 in n and any(word in n for word in (
        "nozzle", "bed", "chamber", "filament", "ace", "slot", "fan", "speed", "camera",
        "light", "pause_button", "resume", "stop"))}
    assert unexpected == set()
    assert not any(n.startswith(("button.", "number.", "select.", "switch.", "light.",
                                 "camera.")) for n in names)
