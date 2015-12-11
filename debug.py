import logging
import xmpp.debug as xmpp_debug

import config


class XMPPLibDebug(logging.Handler):
    def __init__(self, debug):
        logging.Handler.__init__(self)
        self.debug = debug

    def emit(self, record):
        record_name = record.name.split('.')[0]
        if record_name not in self.debug.active:
            self.debug.active.append(record_name)
        self.debug.Show(record_name, record.getMessage(), record.levelname.lower())


def setup_logging(connection):
    # Add our custom handler to the root logger.
    logger = logging.getLogger()
    connection._DEBUG.validate_flags = False
    handler = XMPPLibDebug(connection._DEBUG)
    logger.addHandler(handler)

    # Set log levels.
    logger.setLevel(logging.INFO)
    logging.getLogger('hangups').setLevel(logging.DEBUG if config.debugHangouts else logging.INFO)
    logging.getLogger('jh_hangups').setLevel(logging.DEBUG if config.debugTransport else logging.INFO)
    logging.getLogger('jh_xmpp').setLevel(logging.DEBUG if config.debugTransport else logging.INFO)
    if config.debugXMPP:
        connection._DEBUG.active_set(['dispatcher', 'socket', 'component'])

    # Set colors.
    connection._DEBUG.colors['__main__'] = xmpp_debug.color_purple
    connection._DEBUG.colors['jh_hangouts'] = xmpp_debug.color_green
    connection._DEBUG.colors['jh_xmpp'] = xmpp_debug.color_green
