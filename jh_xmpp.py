import time
import logging
import threading
from multiprocessing import Queue, Lock
import queue
import urllib.request
import base64
import hashlib
import os

import config
import xmpp
import xmpp.client
import xmpp.protocol
from xmpp.browser import Browser
from xmpp.protocol import Presence, Message, Error, Iq, NodeProcessed, JID, DataForm
from xmpp.protocol import NS_REGISTER, NS_PRESENCE, NS_VERSION, NS_COMMANDS, NS_DISCO_INFO, NS_CHATSTATES, NS_ROSTERX, NS_VCARD, NS_AVATAR, NS_MUC, NS_MUC_UNIQUE, NS_DISCO_ITEMS
from xmpp.simplexml import Node
from toolbox import MucUser
import jh_hangups

NODE_ROSTER = 'roster'
NODE_VCARDUPDATE = 'vcard-temp:x:update x'
NS_CONFERENCE = 'jabber:x:conference'
NS_DELAY = 'urn:xmpp:delay'
NS_XMPP_STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'

xmpp_queue = Queue()
xmpp_lock = Lock()
userfile = None

logger = logging.getLogger(__name__)


class Transport:
    """Represents the connection with the Jabber server"""
    online = 1
    userlist = {}
    discoresults = {}

    def __init__(self, jabber, auserfile):
        self.jabber = jabber
        self.userfile = auserfile
        self.disco = None

    def xmpp_connect(self):
        connected = self.jabber.connect((config.mainServer, config.port))
        logger.debug("Transport is connected: %r.", connected)

        while not connected:
            time.sleep(5)
            connected = self.jabber.connect((config.mainServer, config.port))
            logger.debug("Transport is connected: %r.", connected)
        self.register_handlers()
        logger.debug("Transport is going to auth with the server.")
        connected = self.jabber.auth(config.saslUsername, config.secret)
        logger.debug("Auth returned: %r.", connected)
        return connected

    def register_handlers(self):
        self.jabber.RegisterHandler('presence', self.xmpp_presence)
        self.jabber.RegisterHandler('message', self.xmpp_message)
        self.jabber.RegisterHandler('iq', self.xmpp_iq_discoinfo_results, typ='result', ns=NS_DISCO_INFO)
        self.jabber.RegisterHandler('iq', self.xmpp_iq_register_get, typ='get', ns=NS_REGISTER)
        self.jabber.RegisterHandler('iq', self.xmpp_iq_register_set, typ='set', ns=NS_REGISTER)
        self.jabber.RegisterHandler('iq', self.xmpp_iq_vcard, typ='get', ns=NS_VCARD)

        self.disco = Browser()
        self.disco.PlugIn(self.jabber)
        self.disco.setDiscoHandler(self.xmpp_base_disco, node='', jid=config.jid)
        self.disco.setDiscoHandler(self.xmpp_base_disco, node='', jid='')

    # Disco Handlers
    def xmpp_base_disco(self, con, event, ev_type):
        fromstripped = event.getFrom().getStripped()
        to = event.getTo()
        node = event.getQuerynode()
        # Type is either 'info' or 'items'
        if to == config.jid:
            if node is None:
                # Main JID of the transport
                if ev_type == 'info':
                    return dict(
                        ids=[dict(category='gateway', type='hangouts', name=config.discoName)],
                        features=[NS_VERSION, NS_COMMANDS, NS_PRESENCE, NS_REGISTER, NS_CHATSTATES])
                if ev_type == 'items':
                    alist = [
                        {'node': NODE_ROSTER, 'name': config.discoName + ' Roster', 'jid': config.jid},
                        {'name': config.discoName + ' group chats', 'jid': 'conf@%s' % (config.jid,)},
                    ]
                    return alist
            elif node == NODE_ROSTER:
                if ev_type == 'info':
                    return {'ids': [], 'features': []}
                if ev_type == 'items':
                    # Return a list of the contacts
                    alist = []
                    if fromstripped in self.userlist:
                        for user in self.userlist[fromstripped]['user_list']:
                            alist.append({'jid': '%s@%s' % (user, config.jid),
                                          'name': self.userlist[fromstripped]['user_list'][user]['full_name']})
                    return alist
            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_ITEM_NOT_FOUND']))
                raise NodeProcessed

        elif to.getDomain() == config.jid:
            if to.getNode() == 'conf':
                # JID of the multi-user chat system
                if node is None:
                    if ev_type == 'info':
                        if fromstripped == config.mainServerJID:
                            raise NodeProcessed
                        # Declare the conference node
                        return {'ids': [{'category': 'conference',
                                         'type': 'text',
                                         'name': config.discoName + ' group chats'}],
                                'features': [NS_MUC, NS_MUC_UNIQUE, NS_VERSION, NS_DISCO_INFO, NS_DISCO_ITEMS]}
                    if ev_type == 'items':
                        # Return a list of the available conversations
                        alist = []
                        if fromstripped in self.userlist:
                            for conv_id in self.userlist[fromstripped]['conv_list']:
                                conv = self.userlist[fromstripped]['conv_list'][conv_id]
                                alist.append({'jid': '%s@%s' % (conv_id, config.jid), 'name': conv['topic']})
                        return alist

            elif fromstripped in self.userlist:
                gaia_id = event.getTo().getNode()
                if gaia_id in self.userlist[fromstripped]['user_list']:
                    # JID of a contact.
                    if ev_type == 'info':
                        # Contact exists, declare it as being chatable and also declare that it has a VCard.
                        features = [NS_VCARD, NS_VERSION, NS_CHATSTATES]
                        return {'ids': [{'category': 'client',
                                         'type': 'hangouts',
                                         'name': self.userlist[fromstripped]['user_list'][gaia_id]['full_name']}],
                                'features': features}
                    elif ev_type == 'items':
                        # Contact nodes don't have children.
                        return []

                elif gaia_id in self.userlist[fromstripped]['conv_list']:
                    # JID of a multi-user conversation
                    if ev_type == 'info':
                        # Declare the conversation.
                        conv = self.userlist[fromstripped]['conv_list'][gaia_id]
                        result = {'ids': [{'category': 'conference',
                                           'type': 'text',
                                           'name': gaia_id}],
                                  'features': [NS_MUC, NS_VCARD]}
                        data = {'muc#roominfo_description': conv['topic'],
                                'muc#roominfo_subject': conv['topic'],
                                'muc#roominfo_occupants': len(conv['user_list']),
                                'muc#roomconfig_changesubject': 1}
                        info = DataForm(typ='result', data=data)
                        field = info.setField('FORM_TYPE')
                        field.setType('hidden')
                        field.setValue('http://jabber.org/protocol/muc#roominfo')
                        result['xdata'] = info
                        return result
                    elif ev_type == 'items':
                        # List the participants of the conversation.
                        alist = []
                        conv = self.userlist[fromstripped]['conv_list'][gaia_id]
                        for user in conv['user_list']:
                            alist.append({'jid': '%s@%s' % (user, config.jid),
                                          'name': conv['user_list'][user]})
                        return alist
                else:
                    # User/Conversation does not exist.
                    self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_NOT_ACCEPTABLE']))

        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['MALFORMED_JID']))
            raise NodeProcessed

    # XMPP Handlers
    def xmpp_presence(self, con, event):
        fromjid = event.getFrom()
        fromstripped = fromjid.getStripped()

        if fromstripped in self.userfile:
            if event.getTo().getDomain() == config.jid:
                node = event.getTo().getNode()

                if (fromstripped in self.userlist) and (node in self.userlist[fromstripped]['conv_list']):
                    # Message is about a conversation.
                    conv = self.userlist[fromstripped]['conv_list'][node]
                    conv_id = node

                    if event.getType() == 'available' or event.getType() is None or event.getType() == '':
                        if fromjid not in conv['connected_jids']:
                            # Client joined the conversation:
                            # add it to the list of connected resources and send the user list,
                            # and delete it from the list of invitation.
                            conv['connected_jids'][fromjid] = True
                            if fromjid in conv['invited_jids']:
                                del conv['invited_jids'][fromjid]

                            # Request conversation history from Hangouts.
                            real_conv_id = self.conv_alias_to_gaia_id(conv_id, fromstripped)
                            jh_hangups.hangups_manager.send_message(fromstripped,
                                                                    {'what': 'conversation_history_request',
                                                                     'conv_id': real_conv_id,
                                                                     'sender_jid': fromjid})

                            # According to the protocol, the self-user should the last to be sent.
                            self_user = None
                            for user in conv['user_list']:
                                if user == conv['self_id']:
                                    self_user = user
                                else:
                                    # User is not self, send presence
                                    p = Presence(frm='%s@%s/%s' % (conv_id, config.jid, conv['user_list'][user]),
                                                 to=event.getFrom(),
                                                 payload=[MucUser(role='participant',
                                                                  affiliation='member',
                                                                  jid='%s@%s' % (user, config.jid))])
                                    self.jabber.send(p)

                            if self_user is not None:
                                # Send self user presence
                                muc_user = MucUser(role='participant',
                                                   affiliation='member',
                                                   jid='%s@%s' % (self_user, config.jid))
                                # Code 110 means that this presence is the last of the list
                                # Code 210 means that we renamed the self user.
                                muc_user.addChild('status', {'code': 110})
                                muc_user.addChild('status', {'code': 210})
                                p = Presence(frm='%s@%s/%s' % (conv_id, config.jid, conv['user_list'][self_user]),
                                             to=event.getFrom(),
                                             payload=[muc_user])
                                self.jabber.send(p)

                    elif event.getType() == 'unavailable':
                        # Resource left the conversation:
                        # remove it from the list
                        if event.getFrom() in conv['connected_jids']:
                            del conv['connected_jids'][event.getFrom()]
                    else:
                        self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_FEATURE_NOT_IMPLEMENTED']))

                else:
                    # Message is about the transport.
                    if event.getType() == 'subscribed':
                        if fromstripped in self.userlist:
                            if event.getTo() == config.jid and not self.userfile[fromstripped]['subscribed']:
                                conf = self.userfile[fromstripped]
                                conf['subscribed'] = True
                                self.userfile[fromstripped] = conf
                                self.userfile.sync()

                                # User has subscribed to the transport: send the list of contacts:
                                for user in self.userlist[fromstripped]['user_list']:
                                    self.jabber.send(Presence(frm='%s@%s' % (user, config.jid),
                                                              to=fromjid,
                                                              typ='subscribe'))

                                m = Presence(to=fromjid, frm=config.jid)
                                self.jabber.send(m)
                        else:
                            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_NOT_ACCEPTABLE']))

                    elif event.getType() == 'subscribe':
                        if fromstripped in self.userlist:
                            if event.getTo() == config.jid:
                                # Resource subscribed to the transport: send reply.
                                m = Presence(to=fromjid, frm=config.jid, typ='subscribed')
                                self.jabber.send(m)
                            else:
                                # User tries to add a new contact.
                                # This is currently unsupported.
                                # See: XEP-0100: Gateway Interaction -> 5. Legacy User Use Cases -> 5.1 Add Contact
                                # -> 5.1.2 Alternate Flows -> Example 49. Jabber User Denies Subscription Request:
                                # http://www.xmpp.org/extensions/xep-0100.html#usecases-legacy-add-alt
                                self.jabber.send(Presence(frm=event.getTo(), to=event.getFrom(), typ='unsubscribed'))
                        else:
                            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_NOT_ACCEPTABLE']))

                    elif event.getType() == 'unsubscribed':
                        # should do something more elegant here
                        pass

                    elif event.getType() is None or event.getType() == 'available' or event.getType() == 'invisible':
                        if event.getTo() == config.jid:
                            # Transport user has become connected
                            self.xmpp_resource_join(event.getFrom())

                    elif event.getType() == 'unavailable':
                        if event.getTo() == config.jid:
                            # A resource has become disconnected:
                            # remove it from the list.
                            if fromstripped in self.userlist:
                                # Delete any invitation to multi-user chat.
                                for conv_id in self.userlist[fromstripped]['conv_list']:
                                    conv = self.userlist[fromstripped]['conv_list'][conv_id]
                                    if fromjid in conv['invited_jids']:
                                        del conv['invited_jids'][fromjid]

                                # Remove from the main list
                                if fromjid in self.userlist[fromstripped]['connected_jids']:
                                    del self.userlist[fromstripped]['connected_jids'][fromjid]
                                    if len(self.userlist[fromstripped]['connected_jids']) == 0:
                                        # Removed resource was the last one:
                                        # disconnect Hangout and delete the associated thread.
                                        jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'disconnect'})
                                        hobj = self.userlist[fromstripped]
                                        del self.userlist[fromstripped]
                                        del hobj
                            else:
                                self.jabber.send(Presence(to=fromjid, frm=config.jid, typ='unavailable'))

        else:
            # Need to add auto-unsubscribe on probe events here.
            if event.getType() == 'probe':
                self.jabber.send(Presence(to=event.getFrom(), frm=event.getTo(), typ='unsubscribe'))
                self.jabber.send(Presence(to=event.getFrom(), frm=event.getTo(), typ='unsubscribed'))
            elif event.getType() == 'unsubscribed':
                pass
            elif event.getType() == 'unsubscribe':
                self.jabber.send(Presence(frm=event.getTo(), to=event.getFrom(), typ='unsubscribed'))
            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_REGISTRATION_REQUIRED']))

    @staticmethod
    def get_refresh_token_filename(jid):
            # We store the refresh token in a file named with the sha1 of the jid, to be sure that that name does not
            # contain any invalid or malicious characters.
            hash_object = hashlib.sha1(jid.encode('utf-8'))
            return os.path.join(config.refreshTokenDirectory, hash_object.hexdigest())

    def xmpp_resource_join(self, jid):
        """A new resource has subscribed to the transport. Create a Hangouts thread if none exist and
        send the presence information."""
        fromjid = jid
        fromstripped = fromjid.getStripped()

        if fromstripped in self.userlist:
            # Another resource is already connected:
            # add the new resource to the list.
            self.userlist[fromstripped]['connected_jids'][fromjid] = True
            # Send presence information of connected contacts.
            for user in self.userlist[fromstripped]['user_list']:
                self.send_presence_from_status(fromjid,
                                               '%s@%s' % (user, config.jid),
                                               self.userlist[fromstripped]['user_list'][user]['status'])
        else:
            # No other resource of this user are already connected:
            # check that the user is registered and create a hangout client thread.
            if fromstripped not in self.userfile:
                self.jabber.send(Message(to=fromstripped,
                                         subject='Transport Configuration Error',
                                         body='The transport has found that your configuration could'
                                              ' not be loaded. Please re-register with the transport'))
                del self.userfile[fromstripped]
                self.userfile.sync()
                return

            refresh_token_filename = self.get_refresh_token_filename(fromstripped)
            oauth_code =\
                self.userfile[fromstripped]['oauth_code'] if 'oauth_code' in self.userfile[fromstripped] else ''

            # Spawn a new Hangout client and initialize a new userlist entry.
            try:
                jh_hangups.hangups_manager.spawn_thread(fromstripped,
                                                        xmpp_queue,
                                                        refresh_token_filename,
                                                        oauth_code=oauth_code)
                hobj = {'user_list': {},
                        'conv_list': {},
                        'connected_jids': {fromjid: True}}
                self.userlist[fromstripped] = hobj

                # Send presence transport information.
                self.jabber.send(Presence(frm=config.jid, to=fromjid))

            except jh_hangups.HangupAuthError as e:
                # Auth failed: warn the user.
                error_node = Node('error', {'type': 'auth'})
                error_node.addChild('not-authorized', namespace=NS_XMPP_STANZAS)

                p = Presence(frm=config.jid, to=fromjid, typ='error', payload=[error_node])
                m = Message(typ='error', frm=config.jid, to=fromjid, body='{}'.format(e), payload=[error_node])
                self.jabber.send(p)
                self.jabber.send(m)

    def xmpp_presence_do_update(self, event, fromstripped):
        jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'set_presence',
                                                               'type': event.getType(),
                                                               'show': event.getShow()})

    def xmpp_message(self, con, event):
        from_jid = event.getFrom()
        fromstripped = from_jid.getStripped()

        if event.getTo().getNode() is not None:
            if fromstripped in self.userlist:
                # User is found.
                if event.getTo().getDomain() == config.jid:
                    gaia_id = event.getTo().getNode()

                    if gaia_id in self.userlist[fromstripped]['conv_list']:
                        # Conversation is found in the list => message is in a group chat.

                        if event.getBody() is None and event.getSubject():
                            # Subject change request
                            real_gaia_id = self.conv_alias_to_gaia_id(gaia_id, fromstripped)
                            jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'conversation_rename',
                                                                                   'conv_id': real_gaia_id,
                                                                                   'new_name': event.getSubject()})
                        if (event.getBody() is not None and event.getBody() != '')\
                                and (event.getTo().getResource() is None or event.getTo().getResource() == ''):
                            # Regular message
                            real_gaia_id = self.conv_alias_to_gaia_id(gaia_id, fromstripped)
                            jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'chat_message',
                                                                                   'type': 'group',
                                                                                   'conv_id': real_gaia_id,
                                                                                   'sender_jid': from_jid,
                                                                                   'message': event.getBody()})
                    elif gaia_id in self.userlist[fromstripped]['user_list']:
                        # Message is a regular chat message.
                        if event.getBody() is None:
                            # No body => typing notification.
                            state = 'paused'
                            if event.getTag('composing', namespace=NS_CHATSTATES):
                                state = 'started'
                            # Send notification.
                            jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'typing_notification',
                                                                                   'type': 'one_to_one',
                                                                                   'gaia_id': gaia_id,
                                                                                   'state': state})
                            return

                        resource = 'messenger'
                        if resource == 'messenger':
                            if event.getType() is None or event.getType() == 'normal':
                                # Uninteresting type
                                pass
                            elif event.getType() == 'chat':
                                # Forward the chat message to the Hangouts thread.
                                jh_hangups.hangups_manager.send_message(fromstripped, {'what': 'chat_message',
                                                                                       'type': 'one_to_one',
                                                                                       'gaia_id': event.getTo().getNode(),
                                                                                       'sender_jid': from_jid,
                                                                                       'message': event.getBody()})
                            else:
                                # Unknown type
                                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
                    else:
                        # User or conversation was not found: reply with an error message.
                        error_node = Node('error', {'type': 'cancel', 'code': 503})
                        error_node.addChild('service-unavailable', namespace=NS_XMPP_STANZAS)
                        m = Message(typ='error',
                                    frm='%s@%s' % (gaia_id, config.jid),
                                    to=from_jid,
                                    body='User/Conversation does not exist.', payload=[error_node])
                        self.jabber.send(m)
            else:
                # A message was received from someone who was not registered
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_REGISTRATION_REQUIRED']))
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))

    def xmpp_iq_discoinfo_results(self, con, event):
        self.discoresults[event.getFrom().getStripped().encode('utf8')] = event
        raise NodeProcessed

    def xmpp_iq_vcard(self, con, event):
        fromjid = event.getFrom()
        fromstripped = fromjid.getStripped()
        if fromstripped in self.userfile:
            if event.getTo() == config.jid:
                # Main JID of the transport.
                m = Iq(to=event.getFrom(), frm=event.getTo(), typ='result')
                m.setID(event.getID())
                v = m.addChild(name='vCard', namespace=NS_VCARD)
                v.setTagData(tag='FN', val='Hangouts Transport')
                v.setTagData(tag='NICKNAME', val='Hangouts Transport')
                self.jabber.send(m)

            elif event.getTo().getDomain() == config.jid:
                gaia_id = event.getTo().getNode()

                if fromstripped in self.userlist:
                    if gaia_id in self.userlist[fromstripped]['conv_list']:
                        # JID of a group chat.
                        conv = self.userlist[fromstripped]['conv_list'][gaia_id]
                        m = Iq(to=event.getFrom(), frm=event.getTo(), typ='result')
                        m.setID(event.getID())
                        v = m.addChild(name='vCard', namespace=NS_VCARD)
                        v.setTagData(tag='FN', val=conv['topic'])
                        v.setTagData(tag='NICKNAME', val=conv['topic'])
                        self.jabber.send(m)

                    elif gaia_id in self.userlist[fromstripped]['user_list']:
                        # JID of a regular chat user
                        nick = self.userlist[fromstripped]['user_list'][gaia_id]['full_name']

                        m = Iq(to=event.getFrom(), frm=event.getTo(), typ='result')
                        m.setID(event.getID())
                        v = m.addChild(name='vCard', namespace=NS_VCARD)
                        v.setTagData(tag='FN', val=nick)
                        v.setTagData(tag='NICKNAME', val=nick)

                        # Try to add more information into the card.
                        if self.userlist[fromstripped]['user_list'][gaia_id]['photo_url'] != '':
                            p = v.addChild(name='PHOTO')
                            p.setTagData(tag='TYPE', val='image/jpeg')
                            photo = download_url(self.userlist[fromstripped]['user_list'][gaia_id]['photo_url'])
                            p.setTagData(tag='BINVAL',
                                         val=base64.b64encode(photo).decode())
                        if len(self.userlist[fromstripped]['user_list'][gaia_id]['phones']) > 0:
                            p = v.addChild(name='TEL')
                            p.addChild(name='HOME')
                            p.addChild(name='VOICE')
                            p.addChild(name='NUMBER',
                                       payload=self.userlist[fromstripped]['user_list'][gaia_id]['phones'][0])
                        if len(self.userlist[fromstripped]['user_list'][gaia_id]['emails']) > 0:
                            p = v.addChild(name='EMAIL')
                            p.addChild(name='INTERNET')
                            p.addChild(name='USERID',
                                       payload=self.userlist[fromstripped]['user_list'][gaia_id]['emails'][0])

                        self.jabber.send(m)

                    else:
                        # User/Conversation was not found.
                        self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_ITEM_NOT_FOUND']))
                        raise NodeProcessed

            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_ITEM_NOT_FOUND']))
                raise NodeProcessed
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_ITEM_NOT_FOUND']))
        raise NodeProcessed

    def xmpp_iq_register_get(self, con, event):
        if event.getTo() == config.jid:
            # See: XEP-0100: Gateway Interaction -> 4. Jabber User Use Cases -> 4.1 Register -> 4.1.1 Primary Flow:
            # http://www.xmpp.org/extensions/xep-0100.html#usecases-jabber-register-pri
            url = jh_hangups.get_oauth_url()
            fromjid = event.getFrom().getStripped()
            query_payload = [Node('instructions',
                                  payload='Please open this URL in a webbrowser, follow the instruction and copy '
                                          'the result code here:'),
                             Node('url', payload=[url])]

            if fromjid in self.userfile:
                # User is already registered
                query_payload += [
                    Node('password', payload=['[your code was consumed]']),
                    Node('registered')]
            else:
                query_payload += [Node('password')]

            m = event.buildReply('result')
            m.setQueryNS(NS_REGISTER)
            m.setQueryPayload(query_payload)
            self.jabber.send(m)
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        raise NodeProcessed

    def xmpp_iq_register_set(self, con, event):
        if event.getTo() == config.jid:
            remove = False
            oauth_code = None
            fromjid = event.getFrom()
            fromstripped = event.getFrom().getStripped()

            # Get input from event.
            query = event.getTag('query')
            if query.getTag('password'):
                oauth_code = query.getTagData('password')
            if query.getTag('remove'):
                remove = True

            if not remove and oauth_code:
                # User creates/updates registration..

                # If account already exist, fetch its current config:
                if fromstripped in self.userfile:
                    conf = self.userfile[fromstripped]
                else:
                    conf = {'subscribed': False, 'conv_aliases': {}}

                # Update account file.
                conf['oauth_code'] = oauth_code  # I don't even know why we store this, since it cannot be used twice.
                self.userfile[fromstripped] = conf
                self.userfile.sync()

                # Acknowledge event.
                m = event.buildReply('result')
                self.jabber.send(m)

                # If user is connected, disconnect them.
                if fromstripped in self.userlist:
                    # Stop the thread and send presence information for contacts.
                    jh_hangups.hangups_manager.send_message(fromjid, {'what': 'disconnect'})
                    jh_hangups.hangups_manager.remove_thread(fromjid)
                    self.send_disconnected_presence_events(fromjid)

                    # Remove the user from the user list.
                    del self.userlist[fromstripped]

                # Handle new resources subscription.
                self.xmpp_resource_join(fromjid)

                # Subscribe to user's presence.
                m = Presence(to=fromjid, frm=config.jid, typ='subscribe')
                self.jabber.send(m)

            elif remove:
                # User unregisters from the gateway.
                # See: XEP-0100: Gateway Interaction ->  4.3. Unregister -> 4.3.1. Primary Flow:
                # http://www.xmpp.org/extensions/xep-0100.html#usecases-jabber-unregister-pri

                # If user is connected:
                if fromstripped in self.userlist:
                    # Stop the thread and send presence information for contacts.
                    jh_hangups.hangups_manager.send_message(fromjid, {'what': 'disconnect'})
                    jh_hangups.hangups_manager.remove_thread(fromjid)
                    self.send_disconnected_presence_events(fromstripped)

                    # Remove the user from the user list.
                    del self.userlist[fromstripped]

                # Remove the user from the account file.
                if fromstripped in self.userfile:
                    del self.userfile[fromstripped]
                    self.userfile.sync()

                # Delete the refresh token file.
                refresh_token_filename = self.get_refresh_token_filename(fromstripped)
                try:
                    os.remove(refresh_token_filename)
                except OSError:
                    pass

                # Acknowledge event.
                m = event.buildReply('result')
                self.jabber.send(m)

                # Send presence information.
                m = Presence(to=fromjid, frm=config.jid, typ='unsubscribe')
                self.jabber.send(m)
                m = Presence(to=fromjid, frm=config.jid, typ='unsubscribed')
                self.jabber.send(m)
                m = Presence(to=fromjid, frm=config.jid, typ='unavailable')
                self.jabber.send(m)

            else:
                self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        else:
            self.jabber.send(Error(event, xmpp.protocol.ERRS['ERR_BAD_REQUEST']))
        raise NodeProcessed

    def xmpp_disconnect(self):
        # Transport was disconnected:
        # stop and remove all the Hangouts threads,
        # and try to reconnect.
        for jid in list(self.userlist.keys()):
            # Send presence information.
            self.send_disconnected_presence_events(jid)

            # Stop the thread.
            jh_hangups.hangups_manager.send_message(jid, {'what': 'disconnect'})
            jh_hangups.hangups_manager.remove_thread(jid)

            # Remove the connection information.
            hobj = self.userlist[jid]
            del self.userlist[jid]
            del hobj
        time.sleep(5)
        if not self.jabber.reconnectAndReauth():
            time.sleep(5)
            self.xmpp_connect()

    def send_disconnected_presence_events(self, jid):
        # Send presence information of the transport.
        self.jabber.send(Presence(frm=config.jid, to=jid, typ="unavailable"))

        # Send presence information of all users, to prevent from still showing as connected in the clients.
        if jid in self.userlist:
            for user in self.userlist[jid]['user_list']:
                self.jabber.send(Presence(frm='%s@%s' % (user, config.jid),
                                          to=jid,
                                          typ="unavailable"))

    def create_conv_alias_dict_if_not_exist(self, fromstripped):
        if 'conv_aliases' not in self.userfile[fromstripped]:
            hobj = self.userfile[fromstripped]
            hobj['conv_aliases'] = {}
            self.userfile[fromstripped] = hobj
            self.userfile.sync()

    def conv_alias_to_gaia_id(self, conv_alias, fromstripped):
        self.create_conv_alias_dict_if_not_exist(fromstripped)

        aliases = self.userfile[fromstripped]['conv_aliases']

        for gaia_id in aliases:
            if aliases[gaia_id] == conv_alias:
                return gaia_id

        return conv_alias  # Input is not an alias.

    def gaia_id_to_conv_alias(self, gaia_id, fromstripped):
        self.create_conv_alias_dict_if_not_exist(fromstripped)

        aliases = self.userfile[fromstripped]['conv_aliases']

        if gaia_id in aliases:
            return aliases[gaia_id]

        return gaia_id  # No alias found.

    def send_presence(self, fromjid, jid, typ=None, show=None):
        self.jabber.send(Presence(frm=jid, to=fromjid, typ=typ, show=show))

    def send_presence_from_status(self, fromjid, jid, status='online'):
        if status == 'away':
            self.send_presence(fromjid, jid, show='xa')
        elif status == 'online':
            self.send_presence(fromjid, jid)
        elif status == 'offline':
            self.send_presence(fromjid, jid, typ='unavailable')

    def handle_message(self, message):
        # Handle a message from the hangout thread.
        logger.debug("Handling message from hangouts: %r", message)

        fromjid = message['jid']
        if fromjid not in self.userlist:
            # Thread user is not in the list:
            # do not process the message.
            return

        if message['what'] == 'connected':
            # Hangouts is connected. Send presence information of the transport.
            self.jabber.send(Presence(frm=config.jid, to=fromjid))

            # If we're connected, this means that the oauth code was used. Remove it.
            if 'oauth_code' in self.userfile[fromjid]:
                conf = self.userfile[fromjid]
                del conf['oauth_code']
                self.userfile[fromjid] = conf
                self.userfile.sync()

        elif message['what'] == 'disconnected':
            # Hangouts is disconnected.
            self.send_disconnected_presence_events(fromjid)

        if message['what'] == 'user_list':
            # Receive the list of contacts:
            # Store it and send presence information.
            hobj = self.userlist[fromjid]
            hobj['user_list'] = message['user_list']

            for user_id in message['user_list']:
                user = message['user_list'][user_id]
                p = Presence(frm='%s@%s' % (user['gaia_id'], config.jid),
                             to=fromjid,
                             typ='subscribe',
                             status='Hangouts contact')
                p.addChild(node=Node(NODE_VCARDUPDATE, payload=[Node('nickname', payload=user['full_name'])]))
                self.jabber.send(p)
                self.send_presence_from_status(fromjid, '%s@%s' % (user['gaia_id'], config.jid), user['status'])

        elif message['what'] == 'conv_list':
            # Receive the list of conversation:
            # Store it and initialize the list of connected resources for each.
            hobj = self.userlist[fromjid]
            hobj['conv_list'] = {}
            for conv_id in message['conv_list']:
                aliased_conv_id = self.gaia_id_to_conv_alias(conv_id, fromjid)
                message['conv_list'][conv_id]['conv_id'] = aliased_conv_id
                hobj['conv_list'][aliased_conv_id] = message['conv_list'][conv_id]

            for conv_id in message['conv_list']:
                conv = message['conv_list'][conv_id]
                conv['connected_jids'] = {}
                conv['invited_jids'] = {}

        elif message['what'] == 'presence':
            # Receive presence information of contact:
            # Forward to XMPP.
            if message['gaia_id'] in self.userlist[fromjid]['user_list']:
                self.userlist[fromjid]['user_list'][message['gaia_id']]['status'] = message['status']
            self.send_presence_from_status(fromjid, '%s@%s' % (message['gaia_id'], config.jid), message['status'])

        elif message['what'] == 'chat_message':
            # Receive a chat message.
            if message['type'] == 'one_to_one':
                # Message is between two people: send directly to XMPP contact.
                m = Message(typ='chat',
                            frm='%s@%s' % (message['gaia_id'], config.jid),
                            to=JID(fromjid),
                            body=message['message'])
                m.setTag('active', namespace=NS_CHATSTATES)
                self.jabber.send(m)

            elif message['type'] == 'group':
                # Message is from a multi-user chat.
                message['conv_id'] = self.gaia_id_to_conv_alias(message['conv_id'], fromjid)
                if message['conv_id'] in self.userlist[fromjid]['conv_list']:
                    conv = self.userlist[fromjid]['conv_list'][message['conv_id']]
                    if message['gaia_id'] in conv['user_list']:
                        # Conversation exists:
                        # Send the message to every connected resource.
                        nick = conv['user_list'][message['gaia_id']]
                        for ajid in conv['connected_jids']:
                            m = Message(typ='groupchat',
                                        frm='%s@%s/%s' % (message['conv_id'], config.jid, nick),
                                        to=ajid,
                                        body=message['message'])
                            self.jabber.send(m)
                        # Send an invitation to every resource that did not open the conversation.
                        for ajid in self.userlist[fromjid]['connected_jids']:
                            if ajid not in conv['connected_jids'] and ajid not in conv['invited_jids']:
                                conv['invited_jids'][ajid] = True
                                # See: XEP-0249: Direct MUC Invitations -> 2. How It Works -> Example 1:
                                # http://xmpp.org/extensions/xep-0249.html
                                node = Node('x', {'jid': '%s@%s' % (message['conv_id'], config.jid),
                                                  'reason': 'New messages are in!'})
                                node.setNamespace(NS_CONFERENCE)
                                m = Message(frm=config.jid,
                                            to=ajid,
                                            payload=[node])
                                self.jabber.send(m)

        elif message['what'] == 'typing_notification':
            # Receive a typing notification:
            # Forward to XMPP.
            if message['type'] == 'one_to_one':
                m = Message(typ='chat',
                            frm='%s@%s' % (message['gaia_id'], config.jid),
                            to=JID(fromjid))
                if message['state'] == 'started':
                    m.setTag('composing', namespace=NS_CHATSTATES)
                else:
                    m.setTag('paused', namespace=NS_CHATSTATES)
                self.jabber.send(m)

        elif message['what'] == 'conversation_history':
            message['conv_id'] = self.gaia_id_to_conv_alias(message['conv_id'], fromjid)
            conv = self.userlist[fromjid]['conv_list'][message['conv_id']]
            if message['recipient_jid'] in conv['connected_jids']:
                for event in message['history']:
                    # See: XEP-0045: Multi-User Chat ->7.2.14 Discussion History
                    # -> Example 35. Delivery of Discussion History:
                    # http://xmpp.org/extensions/xep-0045.html#enter-history
                    if event['type'] == 'message':
                        # Regular chat message
                        if event['gaia_id'] in conv['user_list']:
                            nick = conv['user_list'][event['gaia_id']]
                        else:
                            nick = 'Unknown (%s)' % (event['gaia_id'],)
                        m = Message(typ='groupchat',
                                    frm='%s@%s/%s' % (message['conv_id'], config.jid, nick),
                                    to=message['recipient_jid'],
                                    body=event['message'])
                    elif event['type'] == 'rename':
                        # Conversation was renamed
                        m = Message(typ='groupchat',
                                    frm='%s@%s' % (message['conv_id'], config.jid),
                                    to=message['recipient_jid'],
                                    body='Conversation was renamed to: %s.' % (event['new_name']))
                    elif event['type'] == 'invite':
                        # Member has joined
                        m = Message(typ='groupchat',
                                    frm='%s@%s' % (message['conv_id'], config.jid),
                                    to=message['recipient_jid'],
                                    body='%s has invited %s.' % (event['inviter'], event['invited']))
                    elif event['type'] == 'departure':
                        # Member has left
                        m = Message(typ='groupchat',
                                    frm='%s@%s' % (message['conv_id'], config.jid),
                                    to=message['recipient_jid'],
                                    body='%s has left.' % (event['departed'],))
                    else:
                        # Unknown
                        m = Message(typ='groupchat',
                                    frm='%s@%s' % (message['conv_id'], config.jid),
                                    to=message['recipient_jid'],
                                    body='[Unknown event]')

                    m.addChild('delay',
                               attrs={'from': '%s@%s' % (message['conv_id'], config.jid),
                                      'stamp': event['timestamp'].isoformat()},
                               namespace=NS_DELAY)
                    self.jabber.send(m)

                # The room subject can only be sent after the history. Send it here.
                # See: XEP-0045: Multi-User Chat -> 7.2.16 Room Subject:
                # http://xmpp.org/extensions/xep-0045.html#enter-subject
                m = Message(typ='groupchat',
                            frm='%s@%s' % (message['conv_id'], config.jid),
                            to=message['recipient_jid'],
                            subject=conv['topic'])
                self.jabber.send(m)

        elif message['what'] == 'conversation_rename':
            # Group chat was renamed
            message['conv_id'] = self.gaia_id_to_conv_alias(message['conv_id'], fromjid)
            if message['conv_id'] in self.userlist[fromjid]['conv_list']:
                conv = self.userlist[fromjid]['conv_list'][message['conv_id']]
                if conv['topic'] != message['new_name']:
                    conv['topic'] = message['new_name']
                    for ajid in conv['connected_jids']:
                        m = Message(typ='groupchat',
                                    frm='%s@%s' % (message['conv_id'], config.jid),
                                    to=ajid,
                                    subject=message['new_name'])
                        self.jabber.send(m)

        elif message['what'] == 'conversation_add':
            # Group chat was created/found: add it to the list
            hobj = self.userlist[fromjid]
            conv_id = message['conv']['conv_id']
            conv_id = self.gaia_id_to_conv_alias(conv_id, fromjid)

            hobj['conv_list'][conv_id] = message['conv']
            conv = hobj['conv_list'][conv_id]
            conv['connected_jids'] = {}
            conv['invited_jids'] = {}

        elif message['what'] == 'conversation_membership_change':
            # Members were added or removed from group chat
            message['conv_id'] = self.gaia_id_to_conv_alias(message['conv_id'], fromjid)
            if message['conv_id'] in self.userlist[fromjid]['conv_list']:
                conv = self.userlist[fromjid]['conv_list'][message['conv_id']]
                if 'new_members' in message:
                    # Members were added
                    for gaia_id in message['new_members']:
                        conv['user_list'][gaia_id] = message['new_members'][gaia_id]

                        # Send presence information to connected resources
                        for ajid in conv['connected_jids']:
                            p = Presence(frm='%s@%s/%s' % (message['conv_id'],
                                                           config.jid, message['new_members'][gaia_id]),
                                         to=ajid,
                                         payload=[MucUser(role='participant',
                                                          affiliation='member',
                                                          jid='%s@%s' % (gaia_id, config.jid))])
                            self.jabber.send(p)

                if 'old_members' in message:
                    # Members were removed
                    for gaia_id in message['old_members']:
                        if gaia_id in conv['user_list']:
                            del conv['user_list'][gaia_id]

                        # Send presence information to connected resources
                        for ajid in conv['connected_jids']:
                            p = Presence(frm='%s@%s/%s' % (message['conv_id'],
                                                           config.jid, message['old_members'][gaia_id]),
                                         typ='unavailable',
                                         to=ajid,
                                         payload=[MucUser(role='none',
                                                          affiliation='member',
                                                          jid='%s@%s' % (gaia_id, config.jid))])
                            self.jabber.send(p)

                    if conv['self_id'] in message['old_members']:
                        # We are in the list of former members. This means that we left the conversation:
                        # Send a message and delete the conversation.
                        for ajid in conv['connected_jids']:
                            m = Message(typ='groupchat',
                                        frm='%s@%s' % (message['conv_id'], config.jid),
                                        to=ajid,
                                        body='You have left the conversation in another client.')
                            self.jabber.send(m)

                        # Remove the conversation from the list.
                        del self.userlist[fromjid]['conv_list'][message['conv_id']]

        elif message['what'] == 'chat_message_error':
            # A chat message from XMPP was not delivered.
            message['conv_id'] = self.gaia_id_to_conv_alias(message['conv_id'], fromjid)
            if message['conv_id'] in self.userlist[fromjid]['conv_list']:
                error_node = Node('error', {'type': 'cancel', 'code': 503})
                error_node.addChild('service-unavailable', namespace=NS_XMPP_STANZAS)
                if message['type'] == 'one_to_one':
                    frm = '%s@%s' % (message['gaia_id'], config.jid)
                else:
                    frm = '%s@%s' % (message['conv_id'], config.jid)
                m = Message(typ='error',
                            frm=frm,
                            to=message['recipient_jid'],
                            body=message['message'], payload=[error_node])
                self.jabber.send(m)

        else:
            jh_hangups.hangups_manager.send_message(message['jid'], {'what': 'test'})


class XMPPQueueThread(threading.Thread):
    """Thread that process message for XMPP from the queue"""
    def __init__(self, transport):
        super().__init__()
        self.transport = transport

    def run(self):
        # Process messags until the transport wants to stop.
        while self.transport.online == 1:
            try:
                message = xmpp_queue.get(True, 0.01)
            except queue.Empty:
                continue

            xmpp_lock.acquire()
            try:
                self.transport.handle_message(message)
            finally:
                xmpp_lock.release()

        logger.info("Queue thread stopped.")


def download_url(url):
    """Download a file from an URL and return a binary"""
    if not url.startswith('http'):
        url = 'http:' + url
    response = urllib.request.urlopen(url)
    data = response.read()
    return data
