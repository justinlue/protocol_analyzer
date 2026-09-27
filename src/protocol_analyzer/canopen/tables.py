from __future__ import annotations

NMT_COMMANDS = {0x01: "start", 0x02: "stop", 0x80: "enter_pre_operational",
                0x81: "reset_node", 0x82: "reset_communication"}

NMT_STATES = {0x00: "boot-up", 0x04: "stopped", 0x05: "operational", 0x7F: "pre-operational"}

ERROR_REGISTER_BITS = {0: "generic", 1: "current", 2: "voltage", 3: "temperature",
                       4: "communication", 5: "device_profile", 7: "manufacturer"}

# CiA 301 emergency error codes; lookup falls back from the exact code to its 0xFF00 and 0xF000 family.
EMCY_CODES = {
    0x1000: "Generic error",
    0x2000: "Current", 0x2100: "Current, device input side", 0x2200: "Current inside the device",
    0x2300: "Current, device output side",
    0x3000: "Voltage", 0x3100: "Mains voltage", 0x3200: "Voltage inside the device", 0x3300: "Output voltage",
    0x4000: "Temperature", 0x4100: "Ambient temperature", 0x4200: "Device temperature",
    0x5000: "Device hardware",
    0x6000: "Device software", 0x6100: "Internal software", 0x6200: "User software", 0x6300: "Data set",
    0x7000: "Additional modules",
    0x8000: "Monitoring", 0x8100: "Communication", 0x8110: "CAN overrun (objects lost)",
    0x8120: "CAN in error passive mode", 0x8130: "Life guard error or heartbeat error",
    0x8140: "Recovered from bus off", 0x8150: "CAN-ID collision", 0x8200: "Protocol error",
    0x8210: "PDO not processed due to length error", 0x8220: "PDO length exceeded",
    0x8230: "DAM MPDO not processed, destination object not available",
    0x8240: "Unexpected SYNC data length", 0x8250: "RPDO timeout",
    0x9000: "External error",
    0xF000: "Additional functions",
    0xFF00: "Device specific",
}

SDO_ABORTS = {
    0x05030000: "Toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "Client/server command specifier not valid or unknown",
    0x05040002: "Invalid block size",
    0x05040003: "Invalid sequence number",
    0x05040004: "CRC error",
    0x05040005: "Out of memory",
    0x06010000: "Unsupported access to an object",
    0x06010001: "Attempt to read a write only object",
    0x06010002: "Attempt to write a read only object",
    0x06020000: "Object does not exist in the object dictionary",
    0x06040041: "Object cannot be mapped to the PDO",
    0x06040042: "Number and length of mapped objects would exceed PDO length",
    0x06040043: "General parameter incompatibility",
    0x06040047: "General internal incompatibility in the device",
    0x06060000: "Access failed due to a hardware error",
    0x06070010: "Data type does not match, length of service parameter does not match",
    0x06070012: "Data type does not match, length of service parameter too high",
    0x06070013: "Data type does not match, length of service parameter too low",
    0x06090011: "Sub-index does not exist",
    0x06090030: "Invalid value for parameter",
    0x06090031: "Value of parameter written too high",
    0x06090032: "Value of parameter written too low",
    0x06090036: "Maximum value is less than minimum value",
    0x060A0023: "Resource not available: SDO connection",
    0x08000000: "General error",
    0x08000020: "Data cannot be transferred or stored to the application",
    0x08000021: "Data cannot be transferred or stored because of local control",
    0x08000022: "Data cannot be transferred or stored because of the present device state",
    0x08000023: "Object dictionary dynamic generation failed or no object dictionary present",
    0x08000024: "No data available",
}


def emcy_text(code: int) -> str:
    if code == 0:
        return "error reset / no error"
    for mask in (0xFFFF, 0xFF00, 0xF000):
        key = code & mask
        if key and key in EMCY_CODES:
            return EMCY_CODES[key]
    return "unknown error code"


def sdo_abort_text(code: int) -> str:
    return SDO_ABORTS.get(code, "unknown abort code")
