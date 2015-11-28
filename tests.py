import sys
import asyncio
import janus
import os
import logging
import time
import signal
import traceback

sys.path.insert(0, './lib/hangups')
sys.path.insert(0, './lib/xmpp')
from hangups.auth import GoogleAuthError
import hangups
import xmpp
import xmpp.client
from xmpp.browser import Browser
from xmpp.protocol import Presence

import config

_log = logging.getLogger(__name__)

class HangupsThread:
    def __init__(self):
        try:
            cookies = hangups.auth.get_auth_stdin('refresh_token.txt')
        except hangups.GoogleAuthError as e:
            sys.exit('Login failed ({})'.format(e))

        self.conv_list = None
        self.user_list = None

        self.client = hangups.Client(cookies)
        self.client.on_connect.add_observer(self.on_connect)

        loop = asyncio.get_event_loop()
        self.queue = janus.Queue(loop=loop)

        tasks = [asyncio.Task(self.process_queue()), self.client.connect()]
        loop.run_until_complete(asyncio.gather(*tasks))

    @asyncio.coroutine
    def process_queue(self):
        while True:
            message = yield from self.queue.async_q.get()

    @asyncio.coroutine
    def on_connect(self):
        """Handle connecting for the first time."""
        self.user_list, self.conv_list = (
            yield from hangups.build_user_conversation_list(self.client)
        )
        for user in self.user_list.get_all():
            print(user.photo_url)
        # self.conv_list.on_event.add_observer(self.on_event)

class Transport:
    online = 1

    def __init__(self, jabber):
        self.jabber = jabber

    def xmpp_connect(self):
        connected = self.jabber.connect((config.mainServer, config.port))
        if config.dumpProtocol:
            _log.info("connected: %r", connected)
        while not connected:
            time.sleep(5)
            connected = self.jabber.connect((config.mainServer, config.port))
            if config.dumpProtocol:
                _log.info("connected: %r", connected)
        self.register_handlers()
        if config.dumpProtocol:
            _log.info("trying auth")
        connected = self.jabber.auth(config.saslUsername, config.secret)
        if config.dumpProtocol:
            _log.info("auth return: %r", connected)
        return connected

    def register_handlers(self):
        self.jabber.RegisterHandler('presence', self.xmpp_presence)

        self.disco = Browser()
        self.disco.PlugIn(self.jabber)
        self.disco.setDiscoHandler(self.xmpp_base_disco, node='', jid=config.jid)

    # Disco Handlers
    def xmpp_base_disco(self, con, event, ev_type):
        print("DICOOOO")
        fromjid = event.getFrom().__str__()
        to = event.getTo()
        node = event.getQuerynode()
        #Type is either 'info' or 'items'
        if to == config.jid:
            if node == None:
                if ev_type == 'info':
                    return dict(
                        ids=[dict(category='gateway', type='hangouts',
                          name=config.discoName)],
                        features=[NS_VERSION, NS_COMMANDS, NS_PRESENCE])
                if ev_type == 'items':
                    return []
            else:
                self.jabber.send(Error(event, ERR_ITEM_NOT_FOUND))
                raise NodeProcessed
        else:
            self.jabber.send(Error(event, MALFORMED_JID))
            raise NodeProcessed

    #XMPP Handlers
    def xmpp_presence(self, con, event):
        print("xmpp_presence!!")
        fromjid = event.getFrom()
        ev_type = event.getType()
        to = event.getTo()
        if ev_type == 'subscribe':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'subscribe'))
        elif ev_type == 'subscribed':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'subscribed'))
        elif ev_type == 'unsubscribe':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unsubscribe'))
        elif ev_type == 'unsubscribed':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unsubscribed'))
        elif ev_type == 'probe':
            self.jabber.send(Presence(to=fromjid, frm = to))
        elif ev_type == 'unavailable':
            self.jabber.send(Presence(to=fromjid, frm = to, typ = 'unavailable'))
        elif ev_type == 'error':
            return
        else:
            self.jabber.send(Presence(to=fromjid, frm = to))

    def xmpp_disconnect(self):
        time.sleep(5)
        if not self.jabber.reconnectAndReauth():
            time.sleep(5)
            self.xmpp_connect()

def loadConfig():
    configOptions = {}
    for configFile in config.configFiles:
        if os.path.isfile(configFile):
            xmlconfig.reloadConfig(configFile, configOptions)
            config.configFile = configFile
            return
    sys.stderr.write(("Configuration file not found. "
      "You need to create a config file and put it "
      " in one of these locations:\n ")
      + "\n ".join(config.configFiles))
    sys.exit(1)

def sigHandler(signum, frame):
    transport.offlinemsg = 'Signal handler called with signal %s' % (signum,)
    if config.dumpProtocol:
        print('Signal handler called with signal %s' % (signum,))
    transport.online = 0

version = 'unknown'
def logError():
    err = '%s - %s\n' % (time.strftime('%a %d %b %Y %H:%M:%S'), version)
    if logfile != None:
        logfile.write(err)
        traceback.print_exc(file=logfile)
        logfile.flush()
    sys.stderr.write(err)
    traceback.print_exc()

def setup_debugging():
    sys.path.append('/root/pycharm-debug-py3k.egg')
    import pydevd
    pydevd.settrace('192.168.4.47', port=5422, stdoutToServer=True, stderrToServer=True, suspend=False)


if __name__ == '__main__':
    setup_debugging()

    # HangupsThread()

    logfile = None
    if config.debugFile:
        logfile = open(config.debugFile, 'a')

    if config.dumpProtocol:
        debug = ['always', 'nodebuilder']
    else:
        debug = []

    if config.saslUsername:
        sasl = 1
    else:
        config.saslUsername = config.jid
        sasl = 0
    connection = xmpp.client.Component(config.jid, config.port, debug=debug, sasl=sasl, bind=config.useComponentBinding, route=config.useRouteWrap)

    transport = Transport(connection)
    if not transport.xmpp_connect():
        print("Could not connect to server, or password mismatch!")
        sys.exit(1)

    signal.signal(signal.SIGINT, sigHandler)
    signal.signal(signal.SIGTERM, sigHandler)

    while transport.online:
        try:
            connection.Process(1)
        except KeyboardInterrupt:
            _pendingException = sys.exc_info()
            raise _pendingException[0](pendingException[1]).with_traceback(_pendingException[2])
        except IOError:
            transport.xmpp_disconnect()
        except:
            logError()
        if not connection.isConnected():
            transport.xmpp_disconnect()
    connection.disconnect()
