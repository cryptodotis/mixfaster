# This file contains python variables that configure Lamson for email processing.
import logging

# You may add additional parameters such as `username' and `password' if your
# relay server requires authentication, `starttls' (boolean) or `ssl' (boolean)
# for secure connections.
relay_config = {'host': '', 'port': 25}

receiver_config = {'host': '0.0.0.0', 'port': 25}

handlers = ['app.handlers.remailer']

router_defaults = {'host': 'FILL_IN_REMAILER_DOMAIN'}

template_config = {'dir': 'app', 'module': 'templates'}

# the config/boot.py will turn these values into variables set in settings
