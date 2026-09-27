from __future__ import annotations

# Function code (COB-ID & 0x780) -> service, for node-addressed COB-IDs (predefined connection set).
_FUNCTIONS = {
    0x080: "emcy", 0x180: "tpdo1", 0x200: "rpdo1", 0x280: "tpdo2", 0x300: "rpdo2",
    0x380: "tpdo3", 0x400: "rpdo3", 0x480: "tpdo4", 0x500: "rpdo4",
    0x580: "sdo_tx", 0x600: "sdo_rx", 0x700: "heartbeat",
}
_BROADCAST = {0x000: "nmt", 0x080: "sync", 0x100: "time", 0x7E4: "lss", 0x7E5: "lss"}


def classify(can_id: int) -> tuple[str, int | None]:
    """Split an 11-bit COB-ID into (service, Node ID)."""
    if can_id in _BROADCAST:
        return _BROADCAST[can_id], None
    node = can_id & 0x07F
    service = _FUNCTIONS.get(can_id & 0x780)
    if can_id > 0x7FF or node == 0 or service is None:
        return "unknown", None
    return service, node
