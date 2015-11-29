import asyncio
import sys
import threading

from hangups.auth import GoogleAuthError
import hangups.hangouts_pb2 as hangouts_pb2
import hangups

hangups_manager = None


class HangupsManager:
    hangouts_threads = {}

    def spawn_thread(self, jid, xmpp_queue):
        thread = HangupsThread(jid, xmpp_queue)
        self.hangouts_threads[jid] = thread
        thread.start()

    def get_thread(self, jid):
        if not jid in self.hangouts_threads:
            return None
        return self.hangouts_threads[jid]

    def remove_thread(self, jid):
        if jid in self.hangouts_threads:
            del self.hangouts_threads[jid]

    def send_message(self, jid, message):
        thread = self.get_thread(jid)
        if thread is not None:
            thread.call_soon_thread_safe(message)

class HangupsThread(threading.Thread):
    def __init__(self, jid, xmpp_queue):
        super().__init__()

        self.jid = jid
        self.xmpp_queue = xmpp_queue

        try:
            self.cookies = hangups.auth.get_auth_stdin('refresh_token.txt')
        except hangups.GoogleAuthError as e:
            sys.exit('Login failed ({})'.format(e))

        self.conv_list = None
        self.user_list = None
        self.state = None
        self.show = None

    def run(self):
        policy = asyncio.get_event_loop_policy()
        self.loop = policy.new_event_loop()
        policy.set_event_loop(self.loop)

        self.client = hangups.Client(self.cookies)
        self.client.on_connect.add_observer(self.on_connect)

        self.set_state('disconnected')
        self.loop.run_until_complete(self.client.connect())

    def do_nothing(self):
        self.A = True
        while self.A:
            yield from asyncio.sleep(1)
        print("Do nothing terminated!")

    def call_soon_thread_safe(self, message):
        self.loop.call_soon_threadsafe(self.on_message, message)

    def send_message_to_xmpp(self, message):
        message['jid'] = self.jid
        self.xmpp_queue.put(message)

    def set_state(self, state):
        print("Setting state: ", state)
        self.state = state

    def set_presence(self, type, show):
        print("Setting presence: ", type, show)
        self.type = type
        self.show = show

    def on_message(self, message):
        print("Message to process in a corouting: ", message)
        if message['what'] == 'disconnect':
            self.set_state('disconnected')
            #self.client.disconnect()
            self.A = False
        elif message['what'] == 'connect':
            self.set_state('connected')
        elif message['what'] == 'set_presence':
            self.set_presence(message['type'], message['show'])

    @asyncio.coroutine
    def on_connect(self):
        """Handle connecting for the first time."""

        # Get the list of users and conversations
        self.user_list, self.conv_list = (
            yield from hangups.build_user_conversation_list(self.client)
        )

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
            status = 'offline'
            if user.presence.reachable:
                status = 'away'
                if user.presence.available:
                    status = 'online'

            user_list_dict[user.id_.gaia_id] = {
                'chat_id': user.id_.chat_id,
                'gaia_id': user.id_.gaia_id,
                'first_name': user.first_name,
                'full_name': user.full_name,
                'is_self': user.is_self,
                'emails': user.emails._values,
                'photo_url': user.photo_url,
                'status': status
            }
        self.send_message_to_xmpp({'what': 'user_list', 'user_list': user_list_dict})