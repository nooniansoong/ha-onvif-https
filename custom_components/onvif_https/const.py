"""Constants for the ONVIF-over-HTTPS integration."""

DOMAIN = "onvif_https"

CONF_OFF_DELAY = "off_delay"
CONF_VERIFY_SSL = "verify_ssl"

DEFAULT_PORT = 80          # this NVR multiplexes TLS on :80
DEFAULT_OFF_DELAY = 5      # seconds a binary_sensor stays "on" after an event
DEFAULT_VERIFY_SSL = False # self-signed device cert

# Fired on the HA event bus for EVERY notification (build automations on this).
EVENT_RECEIVED = f"{DOMAIN}_event"

# Dispatcher signal (per config entry) binary_sensor listens on.
SIGNAL_EVENT = f"{DOMAIN}_signal"

# Topic keywords we treat as "interesting" active events.
ACTIVE_KEYWORDS = (
    "line", "cross", "field", "intrusion", "region", "tamper",
    "people", "person", "human", "object", "motion", "pir", "face",
)
