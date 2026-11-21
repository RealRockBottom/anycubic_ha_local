"""ACE 2 switches (drying on/off and auto-feed), and a resin printer's LAN connection."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import box_has_dryer
from .coordinator import AnycubicCoordinator
from .entity import AnycubicAceEntity, AnycubicEntity, async_setup_ace_entities


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, add: AddEntitiesCallback) -> None:
    coord: AnycubicCoordinator = entry.runtime_data
    if coord.hs.resin:
        # No ACE on a resin printer; there is the one-client LAN connection to hand over.
        add([AnycubicLanConnectionSwitch(coord)])
        return
    async_setup_ace_entities(
        entry, coord, add,
        lambda box_id: ([AnycubicAceDryingSwitch(coord, box_id)] if box_has_dryer(box_id) else [])
        + [AnycubicAceAutoFeedSwitch(coord, box_id)])


class AnycubicAceDryingSwitch(AnycubicAceEntity, SwitchEntity):
    """Turn the box dryer on/off using the drying temperature/time setpoints."""

    _attr_translation_key = "ace_drying"
    _attr_device_class = SwitchDeviceClass.SWITCH
    _attr_icon = "mdi:weather-sunny"

    def __init__(self, coordinator: AnycubicCoordinator, box_id: int = 0) -> None:
        super().__init__(coordinator, "drying", box_id)

    @property
    def is_on(self) -> bool:
        return bool(self._box and self._box.drying_active)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_send_command(
            "drying_start",
            target_temp=self.coordinator.drying_temp(self._box_id),
            duration=self.coordinator.drying_hours(self._box_id) * 60,
            box_id=self._box_id,
        )
        self._set_optimistic(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_send_command("drying_stop", box_id=self._box_id)
        self._set_optimistic(False)

    def _set_optimistic(self, on: bool) -> None:
        """drying_status is activity-gated and only echoed on the next poll; reflect the
        change now so the switch holds, then let polls reconcile to real state."""
        if self._box is not None:
            self._box.drying_active = on
            self.coordinator.async_notify_write()


class AnycubicAceAutoFeedSwitch(AnycubicAceEntity, SwitchEntity):
    """Automatic filament feed for the loaded slot."""

    _attr_translation_key = "ace_auto_feed"
    _attr_device_class = SwitchDeviceClass.SWITCH
    _attr_icon = "mdi:autorenew"

    def __init__(self, coordinator: AnycubicCoordinator, box_id: int = 0) -> None:
        super().__init__(coordinator, "auto_feed", box_id)

    @property
    def is_on(self) -> bool:
        return bool(self._box and self._box.auto_feed)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_send_command("auto_feed", on=True, box_id=self._box_id)
        self._set_optimistic(1)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_send_command("auto_feed", on=False, box_id=self._box_id)
        self._set_optimistic(0)

    def _set_optimistic(self, value: int) -> None:
        if self._box is not None:
            self._box.auto_feed = value
            self.coordinator.async_notify_write()


class AnycubicLanConnectionSwitch(AnycubicEntity, SwitchEntity):
    """Home Assistant's connection to a resin printer, to hand it over to Photon Workshop.

    The P1 lets one LAN client in at a time. Off leaves the printer to Workshop, with the
    printer's other entities unavailable; on takes it back. An automation can switch it, for
    example from a Workshop process sensor on the PC (HASS.Agent).
    """

    _attr_translation_key = "lan_connection"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: AnycubicCoordinator) -> None:
        super().__init__(coordinator, "lan_connection")

    @property
    def available(self) -> bool:
        # Always: it is how the connection is switched back on, while the printer's other
        # entities are unavailable because it is off.
        return True

    @property
    def is_on(self) -> bool:
        return not self.coordinator.lan_released

    @property
    def icon(self) -> str:
        return "mdi:lan-connect" if self.is_on else "mdi:lan-disconnect"

    async def async_turn_on(self, **kwargs) -> None:
        await self.coordinator.async_set_lan_connected(True)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        await self.coordinator.async_set_lan_connected(False)
        self.async_write_ha_state()
