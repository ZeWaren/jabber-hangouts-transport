import logging
import xmpp.debug as xmpp_debug
import types

import config


def xmpp_debug_show(self, msg, flag=None, prefix=None, sufix=None, lf=0):
    """This function replace method show in xmpp.debug"""
    if prefix:
        msg = prefix + msg
    if sufix:
        msg = msg + sufix
    logger = logging.getLogger('xmpp')
    logger.debug(msg)


class Formatter(logging.Formatter):
    module_colors = {}

    """Format log entries as would the XMPP library"""
    def __init__(self, fmt=None, datefmt=None, style='%'):
        self.enable_colors = False
        super().__init__(fmt="%(name)s %(levelname)s %(message)s", datefmt=datefmt, style=style)

    def format(self, record):
        if self.enable_colors and record.name in self.module_colors:
            color = self.module_colors[record.name]
        else:
            color = ''
        record.levelname = record.levelname.lower()

        record.name = record.name.split('.')[0]
        record.name = (record.name+' '*12)[:12]
        record.levelname = (record.levelname+' '*6)[:6]

        if self.enable_colors and record.levelno > logging.WARNING:
            color_red = chr(27) + "[31m"
            record.msg = color_red + record.msg

        color_none = chr(27) + "[0m" if self.enable_colors else ''
        return color + super().format(record) + color_none


def setup_logging(connection):
    # Prepare the handlers and formatters.
    formatter = Formatter()
    formatter.module_colors = {
        '__main__': chr(27) + "[35;1m" # purple
    }
    if config.logFile:
        default_handler = logging.FileHandler(config.logFile)
        xmpp_handler = logging.FileHandler(config.logFile)
        xmpp_debug.colors_enabled = False
    else:
        default_handler = logging.StreamHandler()
        xmpp_handler = logging.StreamHandler()
        formatter.enable_colors = True
    default_handler.setFormatter(formatter)
    xmpp_formatter = logging.Formatter(fmt="%(message)s")
    xmpp_handler.setFormatter(xmpp_formatter)

    # Configure the root handler.
    logger = logging.getLogger()
    logger.addHandler(default_handler)
    logger.setLevel(logging.INFO)

    # Configure the module handlers.
    l = logging.getLogger('xmpp')
    l.propagate = False
    l.setLevel(logging.DEBUG if config.debugXMPP else logging.INFO)
    l.addHandler(xmpp_handler)

    l = logging.getLogger('hangups')
    l.propagate = False
    l.setLevel(logging.DEBUG if config.debugHangouts else logging.INFO)
    l.addHandler(default_handler)

    l = logging.getLogger('jh_hangups')
    l.propagate = False
    l.setLevel(logging.DEBUG if config.debugTransport else logging.INFO)
    l.addHandler(default_handler)

    l = logging.getLogger('jh_xmpp')
    l.propagate = False
    l.setLevel(logging.DEBUG if config.debugTransport else logging.INFO)
    l.addHandler(default_handler)

    # Replace the show() method of the XMPP library, to pipe the log messages into logging instead of their mechanism.
    connection._DEBUG.show = types.MethodType(xmpp_debug_show, connection._DEBUG)
    connection._DEBUG.prefix = ''
    if config.debugXMPP:
        connection._DEBUG.active_set(['dispatcher', 'socket', 'component'])

    # Set colors.
    connection._DEBUG.colors['__main__'] = xmpp_debug.color_purple
    connection._DEBUG.colors['jh_hangouts'] = xmpp_debug.color_green
    connection._DEBUG.colors['jh_xmpp'] = xmpp_debug.color_green
