# TP-Link TD-W9960 API client

An example implementation of authentication and E2E comms. via the /cgi_gdpr API endpoint on official TP-Link firmware.

### Compatible (tested) versions
* **Firmware:** 1.2.0 0.8.0 v009d.0 Build 201016 Rel.78709n
* **Hardware:** TD-W9960 v1 00000000 (TD-W9960 V1.20 - blue case)

### Example usage
```
import tplink
import logging

api = tplink.TPLinkClient('192.168.1.1', log_level = logging.INFO)

# Set logout_others to False if you don't want to kick out a logged in user
api.connect('password in plaintext', logout_others = False)

# Print DSL status info
print(api.get_dsl_status())

# Safely logout so others can login
api.logout()
```
___

Licensed under GNU GPL v3
