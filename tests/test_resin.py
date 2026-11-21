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
import asyncio
import base64
import json
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.anycubic.anycubic_local import handshake, mqtt as m
from custom_components.anycubic.anycubic_local.commands import build as build_command
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
    parse_reason,
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
        self.taken_over = False
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
    # What was captured from Photon Workshop on a P1, and nothing else.
    assert {n for n in names if n.startswith("button.")} == {
        f"button.{p1}_pause", f"button.{p1}_resume"}
    assert {n for n in names if n.startswith("light.")} == {f"light.{p1}_camera_light"}
    assert f"camera.{p1}_camera" in names
    # Nothing a resin printer does not have.
    unexpected = {n for n in names if p1 in n and any(word in n for word in (
        "nozzle", "bed", "chamber", "filament", "ace", "slot", "fan", "speed", "stop"))}
    assert unexpected == set()
    assert {n for n in names if n.startswith("switch.")} == {f"switch.{p1}_lan_connection"}
    assert not any(n.startswith(("number.", "select.")) for n in names)


# -------------------------------------------------------------------------- commands
def test_pause_and_resume_are_sent_as_photon_workshop_sends_them():
    """From Workshop 4.2.1's log, as a P1 answered them (pausing/paused, resuming/resumed)."""
    for command in ("pause", "resume"):
        topic, body = build_command("131", "DEV", command, resin=True, ts=1, msgid="m")
        assert topic == f"{PREFIX}/pc/printer/131/DEV/print"
        assert body == {"action": command, "data": {"taskid": ""}, "msgid": "m",
                        "timestamp": 1, "type": "print"}


def test_the_light_and_the_camera_are_sent_as_photon_workshop_sends_them():
    topic, body = build_command("131", "DEV", "camera_light", on=True, resin=True)
    assert topic == f"{PREFIX}/pc/printer/131/DEV/light"
    assert body["action"] == "control" and body["data"] == {"status": 1, "type": 3}
    _, off = build_command("131", "DEV", "camera_light", on=False, resin=True)
    assert off["data"] == {"status": 0, "type": 3}
    for command, action in (("camera_start", "startCapture"), ("camera_stop", "stopCapture")):
        topic, body = build_command("131", "DEV", command, resin=True)
        assert topic == f"{PREFIX}/pc/printer/131/DEV/video"
        assert body["action"] == action and body["data"] == {}


def test_nothing_uncaptured_is_built_for_a_resin_printer():
    import pytest
    for command in ("stop", "set_nozzle_temp", "light", "drying_start"):
        with pytest.raises(ValueError):
            build_command("131", "DEV", command, resin=True)


def test_kobra_commands_are_unchanged():
    topic, body = build_command("20029", "DEV", "pause", ts=1, msgid="m")
    assert topic == f"{PREFIX}/web/printer/20029/DEV/print"
    assert body["data"] == {"taskid": "-1"}


def test_a_p1_pause_is_the_users():
    """Code 401, from the printer's own screen as from Workshop (both captured)."""
    reason = parse_reason({"code": 401, "state": "paused", "msg": ""})
    assert reason.by_user and reason.reason == "Paused by user"


async def test_the_capture_wait_ends_on_the_p1s_start_answer(hass):
    coord = await _coordinator(hass)
    coord._video_report = asyncio.Event()
    coord._on_report("video", {"action": "stopCapture", "state": "done", "code": 200,
                               "msg": "LanStream stop success", "data": None})
    await hass.async_block_till_done()
    assert not coord._video_report.is_set()
    coord._on_report("video", {"action": "startCapture", "state": "initSuccess", "code": 200,
                               "msg": "LanStream start success", "data": None})
    await hass.async_block_till_done()
    assert coord._video_report.is_set()


async def test_a_switched_light_is_tracked(hass):
    coord = await _coordinator(hass)
    coord._on_report("light", {"action": "control", "state": "done", "code": 200,
                               "data": {"type": 3, "status": 1}})
    await hass.async_block_till_done()
    assert coord.data.camera_light.on is True


# ------------------------------------------- another client takes the session (Workshop)
def test_a_resin_session_ended_by_the_printer_is_not_reconnected_by_paho():
    """Tested on a P1: with paho reconnecting at once, Photon Workshop lost the session to
    Home Assistant and could no longer start a print."""
    client = m.AnycubicMqtt(HS, on_report=lambda t, d: None, client_factory=FakeClient)
    client.connect()
    stopped = []
    client._c.disconnect = lambda: stopped.append(True)
    client._c.on_disconnect(client._c, None, 7)
    assert client.taken_over and not client.connected
    assert stopped == [True], "paho was left to reconnect"


def test_a_kobra_session_drop_still_reconnects_on_its_own():
    kobra = HandshakeResult("1.2.3.4", 9883, "u", "p", "DEV", "20029", "SER")
    client = m.AnycubicMqtt(kobra, on_report=lambda t, d: None, client_factory=FakeClient)
    client.connect()
    stopped = []
    client._c.disconnect = lambda: stopped.append(True)
    client._c.on_disconnect(client._c, None, 7)
    assert not client.taken_over and stopped == []


async def test_home_assistant_waits_while_another_client_has_the_printer(hass, monkeypatch):
    import pytest
    from homeassistant.helpers.update_coordinator import UpdateFailed

    from custom_components.anycubic import coordinator as coord_mod

    handshakes = []
    monkeypatch.setattr(coord_mod, "do_handshake", lambda host: handshakes.append(host) or HS)
    clock = [1000.0]
    monkeypatch.setattr(coord_mod.time, "monotonic", lambda: clock[0])

    coord = await _coordinator(hass)
    coord._transport.connected, coord._transport.taken_over = False, True   # Workshop

    with pytest.raises(UpdateFailed, match="5 min"):
        await coord._async_update_data()
    clock[0] += 200
    with pytest.raises(UpdateFailed, match="2 min"):
        await coord._async_update_data()
    assert handshakes == [], "took the printer back while the other client had it"

    clock[0] += 101                                   # the five minutes are up
    await coord._async_update_data()
    assert handshakes == ["1.2.3.4"] and coord._transport.connected

    # Pushed off again a minute later: Workshop is still in use, so wait longer.
    clock[0] += 60
    coord._transport.connected, coord._transport.taken_over = False, True
    with pytest.raises(UpdateFailed, match="15 min"):
        await coord._async_update_data()

    # A session that then lasts half an hour starts the back-off over.
    clock[0] += 901
    await coord._async_update_data()
    clock[0] += coord_mod.RESIN_YIELD_RESET
    coord._apply("status", _envelope(STATUS_FREE))
    coord._transport.connected, coord._transport.taken_over = False, True
    with pytest.raises(UpdateFailed, match="5 min"):
        await coord._async_update_data()


# ------------------------------------------- the LAN connection switch (hand over to Workshop)
async def test_switching_the_lan_connection_off_and_on(hass, monkeypatch):
    import pytest
    from homeassistant.helpers.update_coordinator import UpdateFailed

    from custom_components.anycubic import coordinator as coord_mod

    handshakes = []
    monkeypatch.setattr(coord_mod, "do_handshake", lambda host: handshakes.append(host) or HS)
    coord = await _coordinator(hass)
    first = coord._transport
    assert first.connected and not coord.lan_released

    await coord.async_set_lan_connected(False)
    assert coord.lan_released and coord.print_state.lan_released
    assert coord._transport is None and not first.connected      # the printer is free
    with pytest.raises(UpdateFailed, match="switched off"):
        await coord._async_update_data()
    assert handshakes == [], "reconnected while switched off"

    await coord.async_set_lan_connected(True)
    assert not coord.lan_released and handshakes == ["1.2.3.4"]
    assert coord._transport is not None and coord._transport.connected


async def test_switching_on_forgets_the_workshop_back_off(hass, monkeypatch):
    from custom_components.anycubic import coordinator as coord_mod

    monkeypatch.setattr(coord_mod, "do_handshake", lambda host: HS)
    coord = await _coordinator(hass)
    coord._yield_until, coord._yield_step = 10**12, 2
    await coord.async_set_lan_connected(True)
    assert coord._yield_until is None and coord._yield_step is None


async def test_switched_off_stays_off_across_a_restart(hass):
    from custom_components.anycubic.store import PrintState

    stored = PrintState(lan_released=True).as_dict()
    assert PrintState.from_dict(stored).lan_released
    assert not PrintState.from_dict({}).lan_released           # files from before: on
    coord = AnycubicCoordinator(hass, HS, transport_factory=FakeTransport)
    coord.print_state = PrintState.from_dict(stored)
    await coord.async_start()
    assert coord._transport is None, "took the printer at startup while switched off"


async def test_the_switch_stays_available_while_the_printer_is_released(hass):
    entry = MockConfigEntry(domain=DOMAIN, unique_id="SER-P1", data={"host": "1.2.3.4"})
    entry.add_to_hass(hass)
    with patch("custom_components.anycubic.do_handshake", return_value=HS), \
         patch("custom_components.anycubic.coordinator.do_handshake", return_value=HS), \
         patch("custom_components.anycubic.coordinator.mqtt_mod.AnycubicMqtt", FakeTransport):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        switch = "switch.anycubic_photon_p1_lan_connection"
        assert hass.states.get(switch).state == "on"

        await hass.services.async_call("switch", "turn_off", {"entity_id": switch}, blocking=True)
        await hass.async_block_till_done()
        assert hass.states.get(switch).state == "off"
        assert hass.states.get("sensor.anycubic_photon_p1_status").state == "unavailable"

        await hass.services.async_call("switch", "turn_on", {"entity_id": switch}, blocking=True)
        await hass.async_block_till_done()
        assert hass.states.get(switch).state == "on"
