"""Regression tests for MQTT upload handling of untrusted mesh data."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from unittest.mock import MagicMock


class _EventType:
    PRIVATE_KEY = "private_key"
    DISABLED = "disabled"
    ERROR = "error"


def _install_import_stubs() -> None:
    sys.modules.setdefault("homeassistant", MagicMock())
    sys.modules.setdefault("homeassistant.config_entries", MagicMock())
    sys.modules.setdefault("homeassistant.core", MagicMock())

    const = sys.modules.setdefault("custom_components.meshcore.const", MagicMock())
    const.CONF_MQTT_BROKERS = "mqtt_brokers"
    const.CONF_MQTT_DECODER_CMD = "mqtt_decoder_cmd"
    const.CONF_MQTT_IATA = "mqtt_iata"
    const.CONF_MQTT_TOKEN_TTL_SECONDS = "mqtt_token_ttl_seconds"
    const.CONF_NAME = "name"
    const.CONF_PUBKEY = "pubkey"

    events = sys.modules.setdefault("meshcore.events", MagicMock())
    events.EventType = _EventType

    mqtt_client = types.ModuleType("paho.mqtt.client")
    mqtt_client.MQTT_ERR_SUCCESS = 0
    mqtt_client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
    mqtt_client.Client = MagicMock()
    sys.modules.setdefault("paho", types.ModuleType("paho"))
    sys.modules.setdefault("paho.mqtt", types.ModuleType("paho.mqtt"))
    sys.modules["paho.mqtt.client"] = mqtt_client

    nacl = sys.modules.setdefault("nacl", types.ModuleType("nacl"))
    bindings = types.ModuleType("nacl.bindings")
    bindings.crypto_scalarmult_ed25519_base_noclamp = MagicMock(return_value=b"\x00" * 32)
    sys.modules["nacl.bindings"] = bindings
    nacl.bindings = bindings


_install_import_stubs()

_MQTT_UPLOADER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "custom_components",
    "meshcore",
    "mqtt_uploader.py",
)
_spec = importlib.util.spec_from_file_location(
    "custom_components.meshcore.mqtt_uploader_under_test",
    _MQTT_UPLOADER_PATH,
)
_module = importlib.util.module_from_spec(_spec)
_module.__package__ = "custom_components.meshcore"
sys.modules[_spec.name] = _module
assert _spec.loader is not None
_spec.loader.exec_module(_module)

BrokerConfig = _module.BrokerConfig
MeshCoreMqttUploader = _module.MeshCoreMqttUploader


class _PublishResult:
    rc = 0


class _Client:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, int, bool]] = []

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, payload, qos, retain))
        return _PublishResult()


def _broker(payload_mode: str, *, publish_contact_events: bool = False) -> BrokerConfig:
    return BrokerConfig(
        number=1,
        enabled=True,
        server="mqtt.example",
        port=1883,
        transport="tcp",
        use_tls=False,
        tls_verify=True,
        keepalive=60,
        qos=0,
        username="",
        password="",
        use_auth_token=False,
        token_audience="",
        owner_public_key="",
        owner_email="",
        token_ttl_seconds=3600,
        payload_mode=payload_mode,
        publish_contact_events=publish_contact_events,
        client_id_prefix="meshcore_",
        topic_status="meshcore/status",
        topic_packets="meshcore/packets",
    )


def _uploader(broker: BrokerConfig, client: _Client) -> MeshCoreMqttUploader:
    uploader = MeshCoreMqttUploader.__new__(MeshCoreMqttUploader)
    uploader.node_name = "<img src=x onerror=alert(1)>"
    uploader.public_key = "A" * 64
    uploader._clients = [{"broker": broker, "client": client, "connected": True}]
    uploader._recent_packet_signatures = {}
    uploader._packet_dedupe_ttl_seconds = 1.0
    uploader.logger = MagicMock()
    return uploader


def test_packet_mode_does_not_publish_contact_name_fields():
    client = _Client()
    uploader = _uploader(_broker("packet"), client)

    uploader.publish_raw_event(
        "EventType.RX_LOG_DATA",
        {
            "payload": "01020304",
            "adv_name": "<img src=//example/pixel>",
            "entity_picture": "javascript:alert(1)",
            "icon": "mdi:test",
            "snr": -4,
            "rssi": -110,
        },
    )

    assert len(client.published) == 1
    published = json.loads(client.published[0][1])
    assert "adv_name" not in published
    assert "entity_picture" not in published
    assert "icon" not in published
    assert "<img" not in client.published[0][1]
    assert published["origin"] == "img src=x onerror=alert(1)"
    assert published["origin_slug"] == "img_src_x_onerror_alert_1"


def test_raw_mode_skips_contact_events_by_default():
    client = _Client()
    uploader = _uploader(_broker("raw"), client)

    uploader.publish_raw_event(
        "EventType.CONTACTS",
        {"abc": {"adv_name": "<img src=//example/pixel>"}},
    )

    assert client.published == []


def test_raw_mode_skips_contact_event_repr_by_default():
    client = _Client()
    uploader = _uploader(_broker("raw"), client)

    uploader.publish_raw_event(
        "<EventType.CONTACTS: 17>",
        {"abc": {"adv_name": "<img src=//example/pixel>"}},
    )

    assert client.published == []


def test_raw_mode_contact_events_can_be_explicitly_enabled():
    client = _Client()
    uploader = _uploader(_broker("raw", publish_contact_events=True), client)

    uploader.publish_raw_event(
        "EventType.NEW_CONTACT",
        {"adv_name": "<img src=//example/pixel>"},
    )

    assert len(client.published) == 1
    published = json.loads(client.published[0][1])
    assert published["payload"]["adv_name"] == "<img src=//example/pixel>"
    assert published["security"]["contains_untrusted_mesh_data"] is True
    assert published["security"]["rendering"] == "escape before HTML/DOM use"


def test_raw_mode_never_publishes_channel_info():
    client = _Client()
    uploader = _uploader(_broker("raw", publish_contact_events=True), client)

    uploader.publish_raw_event(
        "EventType.CHANNEL_INFO",
        {"channel_idx": 0, "channel_secret": "00112233445566778899aabbccddeeff"},
    )

    assert client.published == []


def test_raw_mode_never_publishes_private_key():
    client = _Client()
    uploader = _uploader(_broker("raw", publish_contact_events=True), client)

    uploader.publish_raw_event(
        "EventType.PRIVATE_KEY",
        {"private_key": "00" * 64},
    )

    assert client.published == []


def test_raw_mode_non_contact_payload_marks_untrusted_data():
    client = _Client()
    uploader = _uploader(_broker("raw"), client)

    uploader.publish_raw_event(
        "EventType.RX_LOG_DATA",
        {"text": "<script>alert(1)</script>"},
    )

    assert len(client.published) == 1
    published = json.loads(client.published[0][1])
    assert published["payload"]["text"] == "<script>alert(1)</script>"
    assert published["security"]["contains_untrusted_mesh_data"] is True
    assert published["origin"] == "img src=x onerror=alert(1)"
    assert published["origin_slug"] == "img_src_x_onerror_alert_1"
