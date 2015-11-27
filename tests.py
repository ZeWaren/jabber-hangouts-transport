import sys
import asyncio
import janus

sys.path.insert(0, './lib/hangups')
from hangups.auth import GoogleAuthError
import hangups


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

HangupsThread()
