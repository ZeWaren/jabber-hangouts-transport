import sys
import asyncio
import janus
import os
import logging
import time
import signal
import traceback
import shelve

sys.path.insert(0, './lib/hangups')
sys.path.insert(0, './lib/xmpp')
from hangups.auth import GoogleAuthError
import hangups
import xmpp
import xmpp.client
import xmpp.protocol
from xmpp.browser import Browser
from xmpp.protocol import Presence, Message, Error, Iq, NodeProcessed
from xmpp.protocol import NS_REGISTER, NS_PRESENCE, NS_VERSION, NS_COMMANDS, NS_DISCO_INFO, NS_CHATSTATES, NS_ROSTERX
from xmpp.simplexml import Node

import config

_log = logging.getLogger(__name__)

NODE_ROSTER='roster'

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
    userlist = {}
    discoresults = {}

    def __init__(self, jabber, userfile):
        self.jabber = jabber
        self.userfile = userfile

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
        self.jabber.RegisterHandler('message', self.xmpp_message)
        self.jabber.RegisterHandler('iq',self.xmpp_iq_discoinfo_results,typ = 'result', ns=NS_DISCO_INFO)
        self.jabber.RegisterHandler('iq',self.xmpp_iq_register_get, typ = 'get', ns=NS_REGISTER)
        self.jabber.RegisterHandler('iq',self.xmpp_iq_register_set, typ = 'set', ns=NS_REGISTER)

        self.disco = Browser()
        self.disco.PlugIn(self.jabber)
        self.disco.setDiscoHandler(self.xmpp_base_disco, node='', jid=config.jid)

    # Disco Handlers
    def xmpp_base_disco(self, con, event, ev_type):
        print("DICOOOO")
        fromjid = event.getFrom().__str__()
        fromstripped = event.getFrom().getStripped()
        to = event.getTo()
        node = event.getQuerynode()
        #Type is either 'info' or 'items'
        if to == config.jid:
            if node == None:
                if ev_type == 'info':
                    return dict(
                        ids=[dict(category='gateway', type='hangouts',
                          name=config.discoName)],
                        features=[NS_VERSION, NS_COMMANDS, NS_PRESENCE, NS_REGISTER, NS_CHATSTATES])
                if ev_type == 'items':
                    list = [
                        {'node': NODE_ROSTER, 'name': config.discoName + ' Roster', 'jid': config.jid}
                    ]
                    return list
            elif node == NODE_ROSTER:
                if ev_type == 'info':
                    return {'ids':[],'features':[]}
                if ev_type == 'items':
                    list = []
                    list.append({'jid':'test1@hangups.bsdhangup.zwm', 'name':'Jambon'})
                    list.append({'jid':'test2@hangups.bsdhangup.zwm', 'name':'Poulet'})
                    list.append({'jid':'test3@hangups.bsdhangup.zwm', 'name':'Saucisse'})
                    return list
            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_ITEM_NOT_FOUND']))
                raise NodeProcessed
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['MALFORMED_JID']))
            raise NodeProcessed

    #XMPP Handlers
    def xmpp_presence(self, con, event):
        hobj = None
        fromjid = event.getFrom()
        fromstripped = fromjid.getStripped()
        if fromstripped in userfile:
            if event.getTo().getDomain() == config.jid:
                if event.getType() == 'subscribed':
                    if fromstripped in self.userlist:
                        hobj = self.userlist[fromstripped]
                        if event.getTo() == config.jid:
                            conf = userfile[fromstripped]
                            conf['subscribed']=True
                            userfile[fromstripped]=conf
                            userfile.sync()

                            #For each new user check if rosterx is adversited then do the rosterx message, else send a truckload of subscribes.
                            #Part 1, parse the features out of the disco result
                            features = []
                            if event.getFrom().getStripped() in self.discoresults:
                                discoresult = self.discoresults[event.getFrom().getStripped().encode('utf8')]
                                if discoresult.getTag('query').getTag('feature'): features.append(discoresult.getTag('query').getAttr('var'))
                            #Part 2, make the rosterX message
                            if NS_ROSTERX in features:
                                m = Message(to = fromjid, frm = config.jid, subject= 'Yahoo Roster Items', body = 'Items from Yahoo Roster')
                                p = m.setTag('x',namespace = NS_ROSTERX)
                                p.addChild(
                                    name='item',
                                    attrs={'jid':'%s@%s'%('test1',config.jid),'name': 'Jambon', 'action':'add'}
                                )
                                p.addChild(
                                    name='item',
                                    attrs={'jid':'%s@%s'%('test2',config.jid),'name': 'Poulet', 'action':'add'}
                                )
                                self.jabber.send(m)
                                if config.dumpProtocol: print(m)
                            else:
                                self.jabber.send(Presence(frm='%s@%s'%('test1',config.jid),to = fromjid, typ='subscribe', status='Hangouts contact'))
                                self.jabber.send(Presence(frm='%s@%s'%('test2',config.jid),to = fromjid, typ='subscribe', status='Hangouts contact'))
                            m = Presence(to = fromjid, frm = config.jid)
                            self.jabber.send(m)
                    else:
                        self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_NOT_ACCEPTABLE']))

                elif event.getType() == 'subscribe':
                    if fromstripped in self.userlist:
                        hobj = self.userlist[fromstripped]
                        if event.getTo() == config.jid:
                            conf = userfile[fromstripped]
                            conf['usubscribed']=True
                            userfile[fromstripped]=conf
                            userfile.sync()
                            m = Presence(to = fromjid, frm = config.jid, typ = 'subscribed')
                            self.jabber.send(m)
                        else:
                            #add new user case.
                            if event.getStatus() != None:
                                if config.dumpProtocol: print(event.getStatus().encode('utf-8'))
                                status = event.getStatus()
                            else:
                                status = ''
                            self.jabber.send(Presence(frm=event.getTo(), to = event.getFrom(), typ = 'subscribed'))
                    else:
                        self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_NOT_ACCEPTABLE']))
                elif event.getType() == 'unsubscribed':
                    # should do something more elegant here
                    pass
                elif event.getType() == None or event.getType() == 'available' or event.getType() == 'invisible':
                    if fromstripped in self.userlist:
                        self.xmpp_presence_do_update(event, fromstripped)
                    else:
                        try:
                            conf = userfile[fromstripped]
                        except:
                            self.jabber.send(Message(to=fromstripped,subject='Transport Configuration Error',body='The transport has found that your configuration could not be loaded. Please re-register with the transport'))
                            del userfile[fromstripped]
                            userfile.sync()
                            return
                        # TODO: connect hangouts here
                        hobj = {"coucou": "cucu"}
                        self.userlist[fromstripped] = hobj
                elif event.getType() == 'unavailable':
                    # Match resources and remove the newly unavailable one
                    if fromstripped in self.userlist:
                        hobj=self.userlist[fromstripped]
                        #print 'Resource: ', event.getFrom().getResource(), "To Node: ",yid
                    else:
                        self.jabber.send(Presence(to=fromjid,frm = config.jid, typ='unavailable'))
        else:
            # Need to add auto-unsubscribe on probe events here.
            if event.getType() == 'probe':
                self.jabber.send(Presence(to=event.getFrom(), frm=event.getTo(), typ='unsubscribe'))
                self.jabber.send(Presence(to=event.getFrom(), frm=event.getTo(), typ='unsubscribed'))
            elif event.getType() == 'unsubscribed':
                pass
            elif event.getType() == 'unsubscribe':
                self.jabber.send(Presence(frm=event.getTo(),to=event.getFrom(),typ='unsubscribed'))
            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_REGISTRATION_REQUIRED']))

    def xmpp_presence_do_update(self, event, fromstripped):
        pass

    def xmpp_message(self, con, event):
        ev_type = event.getType()
        from_jid = event.getFrom()
        to_jid = event.getTo()
        fromstripped = from_jid.getStripped()
        print("Sending from ", from_jid, " to ", to_jid, ": ", event.getBody())
        if event.getTo().getNode() != None:
            if fromstripped in self.userlist:
                hobject = self.userlist[fromstripped]
                if event.getTo().getDomain() == config.jid:
                    resource = 'messenger'
                    if resource == 'messenger':
                        if event.getType() == None or event.getType() == 'normal':
                            print("Send!")
                        elif event.getType() == 'chat':
                            print("Send!")
                        else:
                            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
            else:
                if config.dumpProtocol: print('no item error')
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_REGISTRATION_REQUIRED']))
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))

    def xmpp_iq_discoinfo_results(self, con, event):
        self.discoresults[event.getFrom().getStripped().encode('utf8')]=event
        raise NodeProcessed

    def xmpp_iq_register_get(self, con, event):
        if event.getTo() == config.jid:
            url = ["http://example.com/?oauth=sdfsdfsdfsdfsdf"]
            auth_token = []
            fromjid = event.getFrom().getStripped()
            queryPayload = [Node('instructions', payload = 'Please open this URL in a webbrowser and copy the result code here:')]
            if fromjid in self.userfile:
                try:
                    url = userfile[fromjid]['url']
                    auth_token = userfile[fromjid]['auth_token']
                except:
                    pass
                queryPayload += [
                    Node('url', payload=url),
                    Node('password', payload=auth_token),
                    Node('registered')]
            else:
                queryPayload += [
                    Node('url', payload=url),
                    Node('password')]
            m = event.buildReply('result')
            m.setQueryNS(NS_REGISTER)
            m.setQueryPayload(queryPayload)
            self.jabber.send(m)
            #Add disco#info check to client requesting for rosterx support
            i= Iq(to=event.getFrom(), frm=config.jid, typ='get',queryNS=NS_DISCO_INFO)
            self.jabber.send(i)
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        raise NodeProcessed

    def xmpp_iq_register_set(self, con, event):
        if event.getTo() == config.jid:
            remove = False
            url = False
            auth_token = False
            fromjid = event.getFrom().getStripped()
            query = event.getTag('query')
            if query.getTag('url'):
                url = query.getTagData('url')
            if query.getTag('password'):
                auth_token = query.getTagData('password')
            if query.getTag('remove'):
               remove = True
            if not remove and url and auth_token:
                if fromjid in self.userfile:
                    conf = self.userfile[fromjid]
                else:
                    conf = {}
                conf['url']=url
                conf['auth_token']=auth_token
                print('Conf: ',conf)
                self.userfile[fromjid]=conf
                self.userfile.sync()
                m=event.buildReply('result')
                self.jabber.send(m)
                self.userlist[fromjid] = {"coucou":"cucu"}
                # TODO: Connect Hangouts here
            elif remove and not url and not auth_token:
                if fromjid in self.userlist:
                    del self.userlist[fromjid]
                if fromjid in self.userfile:
                    del self.userfile[fromjid]
                    self.userfile.sync()
                    m = event.buildReply('result')
                    self.jabber.send(m)
                    m = Presence(to = event.getFrom(), frm = config.jid, typ = 'unsubscribe')
                    self.jabber.send(m)
                    m = Presence(to = event.getFrom(), frm = config.jid, typ = 'unsubscribed')
                    self.jabber.send(m)
                else:
                    self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        raise NodeProcessed


    def xmpp_disconnect(self):
        for each in self.userlist.keys():
            hobj =self.userlist[each]
            del self.userlist[hobj.fromjid]
            del hobj
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

    userfile = shelve.open(config.spoolFile)
    userfile["coucou"] = "cucu"

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

    transport = Transport(connection, userfile)
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
            raise _pendingException[0](_pendingException[1]).with_traceback(_pendingException[2])
        except IOError:
            transport.xmpp_disconnect()
        except:
            logError()
        if not connection.isConnected():
            transport.xmpp_disconnect()
    connection.disconnect()
