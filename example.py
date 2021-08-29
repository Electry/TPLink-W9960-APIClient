import tplink
import logging

api = tplink.TPLinkClient('192.168.1.1', log_level = logging.INFO)

# Set logout_others to False if you don't want to kick out a logged in user
api.connect('password in plaintext', logout_others = False)

# Print DSL status info
print(api.get_dsl_status())

# Safely logout so others can login
api.logout()
