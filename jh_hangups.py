import asyncio
import sys
import threading
import logging

from hangups.auth import OAUTH2_LOGIN_URL
import hangups.hangouts_pb2 as hangouts_pb2
from hangups.conversation_event import ChatMessageEvent, RenameEvent, MembershipChangeEvent
from hangups.exceptions import NetworkError
import hangups

hangups_manager = None
logger = logging.getLogger(__name__)


def get_oauth_url():
    """Return the URL the user must follow to obtain a refresh token"""
    return OAUTH2_LOGIN_URL


def presence_to_status(presence):
    """Convert a pb2 presence object to a presence description string."""
    status = 'offline'
    if presence.reachable:
        status = 'away'
        if presence.available:
            status = 'online'
    return status


class HangupAuthError(Exception):

    """Exception raised when auth fails."""


class HangupsManager:
    """Manage the different Hangouts threads."""
    hangouts_threads = {}

    def spawn_thread(self, jid, xmpp_queue, refresh_token_filename, oauth_code=""):
        """Create a new Hangouts connection"""
        thread = HangupsThread(jid, xmpp_queue, refresh_token_filename, oauth_code=oauth_code)
        self.hangouts_threads[jid] = thread
        thread.start()

    def get_thread(self, jid):
        """Get a specific Hangouts thread."""
        if jid not in self.hangouts_threads:
            return None
        return self.hangouts_threads[jid]

    def remove_thread(self, jid):
        """Remove a specific thread from the list."""
        if jid in self.hangouts_threads:
            del self.hangouts_threads[jid]

    def send_message(self, jid, message):
        """Send work to a thread."""
        thread = self.get_thread(jid)
        if thread is not None:
            thread.call_soon_thread_safe(message)


class HangupsThread(threading.Thread):
    """Represent a connection with Hangouts."""

    def __init__(self, jid, xmpp_queue, refresh_token_filename, oauth_code=""):
        super().__init__()

        self.jid = jid
        self.refresh_token_filename = refresh_token_filename
        self.xmpp_queue = xmpp_queue

        try:
            self.cookies = hangups.auth.get_auth(lambda: oauth_code, self.refresh_token_filename)
        except hangups.GoogleAuthError as e:
            raise HangupAuthError('Login failed ({})'.format(e))

        self.conv_list = None
        self.user_list = None
        self.state = None
        self.show = None
        self.loop = None
        self.client = None
        self.type = None
        self.known_conservations = set()  # Maintain a list of conversations sent to XMPP

    def run(self):
        """Start the main loop."""
        policy = asyncio.get_event_loop_policy()
        self.loop = policy.new_event_loop()
        policy.set_event_loop(self.loop)

        self.client = hangups.Client(self.cookies)
        self.client.on_connect.add_observer(self.on_connect)
        self.client.on_disconnect.add_observer(self.on_disconnect)
        self.client.on_reconnect.add_observer(self.on_reconnect)

        self.set_state('disconnected')
        self.loop.run_until_complete(self.client.connect())
        print("Hangup thread stopped")

    def call_soon_thread_safe(self, message):
        """Allow self.on_message to be called inside the asyncio loop.
           Can be called from a different thread."""
        if self.loop is not None:
            self.loop.call_soon_threadsafe(asyncio.async, self.on_message(message))

    def send_message_to_xmpp(self, message):
        """Push a message to the XMPP message queue."""
        message['jid'] = self.jid
        self.xmpp_queue.put(message)

    def set_state(self, state):
        print("Setting state: ", state)
        self.state = state

    def set_presence(self, typ, show):
        print("Setting presence: ", typ, show)
        self.type = typ
        self.show = show

    @asyncio.coroutine
    def chat_message(self, message):
        """Receive a message from XMPP, and forward it to Hangouts."""
        if message['message'] is None:
            return
        if message['type'] == 'one_to_one':
            conv = self.conv_list.get_one_to_one_with_user(message['gaia_id'])
            if conv:
                segments = hangups.ChatMessageSegment.from_str(message['message'])
                try:
                    yield from conv.send_message(segments)
                except NetworkError as e:
                    # Hangouts refused our message: warn XMPP.
                    self.send_message_to_xmpp({'what': 'chat_message_error',
                                               'type': 'one_to_one',
                                               'gaia_id': message['gaia_id'],
                                               'message': 'Failed to send message. Reason: {}.'.format(e),
                                               'recipient_jid': message['sender_jid']})
        elif message['type'] == 'group':
            conv = self.conv_list.get_from_sha1_id(message['conv_id'])
            if conv:
                segments = hangups.ChatMessageSegment.from_str(message['message'])
                try:
                    yield from conv.send_message(segments)
                except NetworkError as e:
                    # Hangouts refused our message: warn XMPP.
                    self.send_message_to_xmpp({'what': 'chat_message_error',
                                               'type': 'group',
                                               'conv_id': message['conv_id'],
                                               'message': 'Failed to send message. Reason: {}.'.format(e),
                                               'recipient_jid': message['sender_jid']})

    @asyncio.coroutine
    def typing_notification(self, message):
        """Receive a typing notification from XMPP, and forward it to Hangouts."""
        if message['type'] == 'one_to_one':
            conv = self.conv_list.get_one_to_one_with_user(message['gaia_id'])
            if conv:
                typ = hangouts_pb2.TYPING_TYPE_PAUSED
                if message['state'] == 'started':
                    typ = hangouts_pb2.TYPING_TYPE_STARTED
                yield from conv.set_typing(typ)

    @asyncio.coroutine
    def conversation_history_request(self, message):
        """XMPP asks for history. Fetch and forward it."""
        conv = self.conv_list.get_from_sha1_id(message['conv_id'])
        if conv:
            # Get the latest events
            events = yield from conv.get_n_last_events(50)

            # Build a dictionary list payload
            history = []
            for event in events:
                if isinstance(event, ChatMessageEvent):
                    history.append({
                        'type': 'message',
                        'message': event.text,
                        'timestamp': event.timestamp,
                        'gaia_id': event.user_id.gaia_id
                    })
                elif isinstance(event, RenameEvent):
                    history.append({
                        'type': 'rename',
                        'new_name': event.new_name,
                        'timestamp': event.timestamp,
                    })
                elif isinstance(event, MembershipChangeEvent):
                    event_users = [conv.get_user(user_id) for user_id in event.participant_ids]
                    if event.type_ == hangups.MEMBERSHIP_CHANGE_TYPE_JOIN:
                        for user in event_users:
                            inviter = conv.get_user(event.user_id)
                            history.append({
                                'type': 'invite',
                                'inviter': inviter.unique_full_name,
                                'invited': user.unique_full_name,
                                'timestamp': event.timestamp,
                            })
                    elif event.type_ == hangups.MEMBERSHIP_CHANGE_TYPE_LEAVE:
                        for user in event_users:
                            history.append({
                                'type': 'departure',
                                'departed': user.unique_full_name,
                                'timestamp': event.timestamp,
                            })

            # Send data to XMPP
            self.send_message_to_xmpp({'what': 'conversation_history',
                                       'conv_id': message['conv_id'],
                                       'history': history,
                                       'recipient_jid': message['sender_jid']})

    @asyncio.coroutine
    def conversation_rename(self, message):
        """XMPP renamed a conversation."""
        conv = self.conv_list.get_from_sha1_id(message['conv_id'])
        if conv and message['new_name'] != '':
            yield from conv.rename(message['new_name'])

    @asyncio.coroutine
    def on_message(self, message):
        """Receive a message from XMPP"""
        try:
            if message['what'] == 'disconnect':
                self.set_state('disconnected')
                yield from self.client.disconnect()
                self.loop.stop()
            elif message['what'] == 'connect':
                self.set_state('connected')
            elif message['what'] == 'set_presence':
                self.set_presence(message['type'], message['show'])
            elif message['what'] == 'chat_message':
                yield from self.chat_message(message)
            elif message['what'] == 'typing_notification':
                yield from self.typing_notification(message)
            elif message['what'] == 'conversation_history_request':
                yield from self.conversation_history_request(message)
            elif message['what'] == 'conversation_rename':
                yield from self.conversation_rename(message)
        except NetworkError as e:
            logger.exception(e)

    @asyncio.coroutine
    def on_connect(self):
        """Hangouts is connected."""
        self.send_message_to_xmpp({'what': 'connected'})

        # Get the list of users and conversations
        self.user_list, self.conv_list = (
            yield from hangups.build_user_conversation_list(self.client)
        )

        self.user_list.on_presence.add_observer(self.on_presence)
        self.conv_list.on_event.add_observer(self.on_event)
        self.conv_list.on_typing.add_observer(self.on_typing)

        # Query presence information for user list
        presence_request = hangouts_pb2.QueryPresenceRequest(
            request_header=self.client.get_request_header(),
            participant_id=[
                hangouts_pb2.ParticipantId(gaia_id=user_id.gaia_id,
                                           chat_id=user_id.chat_id) for user_id in self.user_list._user_dict.keys()],
            field_mask=[
                hangouts_pb2.FIELD_MASK_REACHABLE,
                hangouts_pb2.FIELD_MASK_AVAILABLE,
                hangouts_pb2.FIELD_MASK_DEVICE])
        presence_response = yield from self.client.query_presence(presence_request)
        for presence_result in presence_response.presence_result:
            self.user_list.set_presence_from_presence_result(presence_result)

        # Send user list to XMPP
        user_list_dict = {}
        for user in self.user_list.get_all():
            user_list_dict[user.id_.gaia_id] = {
                'chat_id': user.id_.chat_id,
                'gaia_id': user.id_.gaia_id,
                'first_name': user.first_name,
                'full_name': user.unique_full_name,
                'is_self': user.is_self,
                'emails': user.emails._values,
                'phones': user.phones._values,
                'photo_url': user.photo_url,
                'status': presence_to_status(user.presence),
                'status_message': user.get_mood_message(),
            }
        self.send_message_to_xmpp({'what': 'user_list', 'user_list': user_list_dict})

        # Send conversation list to XMPP
        conv_list_dict = {}
        for conv in self.conv_list.get_all():
            self.known_conservations.add(conv.id_)
            if conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_GROUP:
                user_list = {}
                self_gaia_id = None
                for user in conv.users:
                    user_list[user.id_.gaia_id] = user_list_dict[user.id_.gaia_id]['full_name']\
                        if user.id_.gaia_id in user_list_dict else user.id_.gaia_id
                    if user.is_self:
                        # XMPP needs to know which user is itself.
                        self_gaia_id = user.id_.gaia_id
                conv_list_dict[conv.id_sha1] = {
                    'conv_id': conv.id_sha1,
                    'topic': conv.name,
                    'user_list': user_list,
                    'self_id': self_gaia_id,
                }
        self.send_message_to_xmpp({'what': 'conv_list',
                                   'conv_list': conv_list_dict,
                                   'self_gaia': self.user_list._self_user.id_.gaia_id})

    @asyncio.coroutine
    def on_disconnect(self):
        """Hangouts is disconnected"""
        self.send_message_to_xmpp({'what': 'disconnected'})

    @asyncio.coroutine
    def on_reconnect(self):
        """Hangouts reconnected"""
        self.send_message_to_xmpp({'what': 'connected'})

        # Send presence information for contacts.
        for user in self.user_list.get_all():
            self.send_message_to_xmpp({'what': 'presence',
                                       'gaia_id': user.id_.gaia_id,
                                       'status': presence_to_status(user.presence),
                                       'status_message': user.get_mood_message()})

    @asyncio.coroutine
    def on_presence(self, user, presence):
        """Receive presence information from Hangouts, and forward it to XMPP."""
        self.send_message_to_xmpp({'what': 'presence',
                                   'gaia_id': user.id_.gaia_id,
                                   'status': presence_to_status(presence),
                                   'status_message': user.get_mood_message()})

    def on_event(self, conv_event):
        """Receive event from Hangouts."""
        conv = self.conv_list.get(conv_event.conversation_id)
        user = conv.get_user(conv_event.user_id)

        if conv.id_ not in self.known_conservations:
            # Conversation is not in the list of conversations that XMPP is aware of: send it beforehand.
            self.known_conservations.add(conv.id_)

            user_list = {}
            self_gaia_id = None
            for user in conv.users:
                user_list[user.id_.gaia_id] = user.unique_full_name
                if user.is_self:
                    # XMPP needs to know which user is itself.
                    self_gaia_id = user.id_.gaia_id

            conv_dict = {
                'conv_id': conv.id_sha1,
                'topic': conv.name,
                'user_list': user_list,
                'self_id': self_gaia_id,
            }
            self.send_message_to_xmpp({'what': 'conversation_add',
                                       'conv': conv_dict})

        if isinstance(conv_event, hangups.ChatMessageEvent):
            # Event is a chat message: foward it to XMPP.
            if conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_ONE_TO_ONE:
                if not user.is_self:
                    self.send_message_to_xmpp({'what': 'chat_message',
                                               'type': 'one_to_one',
                                               'gaia_id': user.id_.gaia_id,
                                               'message': conv_event.text})
            elif conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_GROUP:
                self.send_message_to_xmpp({'what': 'chat_message',
                                           'type': 'group',
                                           'conv_id': conv.id_sha1,
                                           'gaia_id': user.id_.gaia_id,
                                           'message': conv_event.text})
        elif isinstance(conv_event, RenameEvent):
            # Conversation was renamed
            if conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_GROUP:
                self.send_message_to_xmpp({'what': 'conversation_rename',
                                           'conv_id': conv.id_sha1,
                                           'new_name': conv_event.new_name})
        elif isinstance(conv_event, MembershipChangeEvent):
            # Members joined or left a conversation
            if conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_GROUP:
                message = {'what': 'conversation_membership_change',
                           'conv_id': conv.id_sha1}

                event_users = [conv.get_user(user_id) for user_id in conv_event.participant_ids]
                if conv_event.type_ == hangups.MEMBERSHIP_CHANGE_TYPE_JOIN:
                    new_members = {}
                    for user in event_users:
                        new_members[user.id_.gaia_id] = user.unique_full_name
                    message['new_members'] = new_members
                elif conv_event.type_ == hangups.MEMBERSHIP_CHANGE_TYPE_LEAVE:
                    old_members = {}
                    for user in event_users:
                        old_members[user.id_.gaia_id] = user.unique_full_name
                    message['old_members'] = old_members

                self.send_message_to_xmpp(message)

    def on_typing(self, typing_message):
        """Receive typing notification from Hangouts, and forward it to XMPP."""
        conv = self.conv_list.get(typing_message.conv_id)
        user = conv.get_user(typing_message.user_id)
        if conv is not None and user is not None:
            typing_states = {
                hangouts_pb2.TYPING_TYPE_UNKNOWN: 'unknown',
                hangouts_pb2.TYPING_TYPE_STARTED: 'started',
                hangouts_pb2.TYPING_TYPE_PAUSED:  'paused',
                hangouts_pb2.TYPING_TYPE_STOPPED: 'stopped',
            }
            if conv._conversation.type == hangouts_pb2.CONVERSATION_TYPE_ONE_TO_ONE:
                if not user.is_self:
                    self.send_message_to_xmpp({'what': 'typing_notification',
                                               'type': 'one_to_one',
                                               'gaia_id': user.id_.gaia_id,
                                               'state': typing_states[typing_message.status]})
