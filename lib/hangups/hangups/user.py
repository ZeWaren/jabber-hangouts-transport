"""User objects."""

from collections import namedtuple
import logging
import asyncio
from . import event
from . import hangouts_pb2


logger = logging.getLogger(__name__)
DEFAULT_NAME = 'Unknown'

UserID = namedtuple('UserID', ['chat_id', 'gaia_id'])
Presence = namedtuple('Presence', ['reachable', 'available', 'device_status', 'mood_setting'])
DeviceStatus = namedtuple('DeviceStatus', ['mobile', 'desktop', 'tablet'])
MoodSetting = namedtuple('MoodSetting', ['mood_message'])


class User(object):

    """A chat user.

    Handles full_name or first_name being None by creating an approximate
    first_name from the full_name, or setting both to DEFAULT_NAME.
    """

    # We maintain a list of full names, to be able to assign new User objects a unique one.
    full_name_list = {}

    def __init__(self, user_id, full_name, first_name, photo_url, emails, phones,
                 is_self, presence, participant_type):
        """Initialize a User."""
        self.id_ = user_id
        self.full_name = full_name if full_name != '' else DEFAULT_NAME
        self.first_name = (first_name if first_name != ''
                           else self.full_name.split()[0])
        self.unique_full_name = self.create_unique_full_name()
        self.photo_url = photo_url
        self.emails = emails
        self.phones = phones
        self.is_self = is_self
        self.presence = presence
        self.participant_type = 'gaia' if participant_type == hangouts_pb2.PARTICIPANT_TYPE_GAIA else 'unknown'

    def create_unique_full_name(self):
        """Create a full name that is unique across every user met so far."""
        if self.full_name in self.full_name_list:
            if self.full_name_list[self.full_name] == self.id_:
                # We are already in the list.
                return self.full_name
        else:
            self.full_name_list[self.full_name] = self.id_
            return self.full_name

        # Full name is already taken:
        # Increment a number until we find an empty slot:
        # 1: Xavier Pichard (2)
        # 2: Xavier Pichard (3)
        # 3: Xavier Pichard (4)
        # ...
        n = 1
        while True:
            n += 1
            full_name = '%s (%d)' % (self.full_name, n)
            if full_name in self.full_name_list:
                if self.full_name_list[full_name] == self.id_:
                    # We are already in the list.
                    return full_name
            else:
                # Empty slot.
                self.full_name_list[full_name] = self.id_
                return full_name

    @staticmethod
    def from_entity(entity, self_user_id):
        """Initialize from a Entity.

        If self_user_id is None, assume this is the self user.
        """
        user_id = UserID(chat_id=entity.id.chat_id,
                         gaia_id=entity.id.gaia_id)
        presence = Presence(reachable=entity.presence.reachable,
                            available=entity.presence.available,
                            device_status=DeviceStatus(mobile=entity.presence.device_status.mobile,
                                     desktop=entity.presence.device_status.desktop,
                                     tablet=entity.presence.device_status.tablet),
                            mood_setting=MoodSetting(mood_message=entity.presence.mood_setting.mood_message.mood_content))

        return User(user_id, entity.properties.display_name,
                    entity.properties.first_name,
                    entity.properties.photo_url,
                    entity.properties.email,
                    entity.properties.phone,
                    (self_user_id == user_id) or (self_user_id is None),
                    presence, hangouts_pb2.PARTICIPANT_TYPE_GAIA)

    @staticmethod
    def from_conv_part_data(conv_part_data, self_user_id):
        """Initialize from ConversationParticipantData.

        If self_user_id is None, assume this is the self user.
        """
        user_id = UserID(chat_id=conv_part_data.id.chat_id,
                         gaia_id=conv_part_data.id.gaia_id)
        return User(user_id, conv_part_data.fallback_name, None, None, None, None,
                    (self_user_id == user_id) or (self_user_id is None), None, conv_part_data.participant_type)

    def set_presence(self, pb2_presence):
        self.presence = Presence(reachable=pb2_presence.reachable,
                            available=pb2_presence.available,
                            device_status=DeviceStatus(mobile=pb2_presence.device_status.mobile,
                                     desktop=pb2_presence.device_status.desktop,
                                     tablet=pb2_presence.device_status.tablet),
                            mood_setting=MoodSetting(mood_message=pb2_presence.mood_setting.mood_message.mood_content))

    def get_mood_message(self):
        if self.presence is None:
            return ""
        return "".join([segment.text for segment in self.presence.mood_setting.mood_message.segment._values])

class UserList(object):

    """Collection of User instances."""

    def __init__(self, client, self_entity, entities, conv_parts):
        """Initialize the list of Users.

        Creates users from the given Entity and ConversationParticipantData
        instances. The latter is used only as a fallback, because it doesn't
        include a real first_name.
        """

        # Event fired when the client connects for the first time with
        # arguments ().
        self.on_presence = event.Event('UserList.on_presence')

        self._client = client
        self._self_user = User.from_entity(self_entity, None)
        # {UserID: User}
        self._user_dict = {self._self_user.id_: self._self_user}
        # Add each entity as a new User.
        for entity in entities:
            user_ = User.from_entity(entity, self._self_user.id_)
            self._user_dict[user_.id_] = user_
        # Add each conversation participant as a new User if we didn't already
        # add them from an entity.
        for participant in conv_parts:
            self.add_user_from_conv_part(participant)
        logger.info('UserList initialized with {} user(s)'
                    .format(len(self._user_dict)))

        self._client.on_state_update.add_observer(self._on_state_update)

    def get_user(self, user_id):
        """Return a User by their UserID.

        Raises KeyError if the User is not available.
        """
        try:
            return self._user_dict[user_id]
        except KeyError:
            logger.warning('UserList returning unknown User for UserID {}'
                           .format(user_id))
            return User(user_id, DEFAULT_NAME + ' (' + user_id.gaia_id + ')', None,
                        None, None, None, False, None, hangouts_pb2.PARTICIPANT_TYPE_UNKNOWN)

    def get_all(self):
        """Returns all the users known"""
        return self._user_dict.values()

    def add_user_from_conv_part(self, conv_part):
        """Add new User from ConversationParticipantData"""
        user_ = User.from_conv_part_data(conv_part, self._self_user.id_)
        if user_.id_ not in self._user_dict:
            logging.warning('Adding fallback User: {}'.format(user_))
            self._user_dict[user_.id_] = user_
        return user_

    def set_presence_from_presence_result(self, presence_result):
        user_id = UserID(chat_id=presence_result.user_id.chat_id,
                         gaia_id=presence_result.user_id.gaia_id)
        user = self.get_user(user_id)
        user.set_presence(presence_result.presence)

    @asyncio.coroutine
    def _on_state_update(self, state_update):
        """Receive a StateUpdate"""
        if state_update.HasField('conversation'):
            self._handle_conversation(state_update.conversation)

        notification_type = state_update.WhichOneof('state_update')
        if notification_type == 'presence_notification':
            yield from self._handle_presence_notification(
                state_update.presence_notification
            )

    def _handle_conversation(self, conversation):
        """Receive Conversation and update list of users"""
        for participant in conversation.participant_data:
            self.add_user_from_conv_part(participant)

    @asyncio.coroutine
    def _handle_presence_notification(self, presence_notification):
        """Receive PresenceNotification and update the user."""
        for presence in presence_notification.presence:
            user_id = UserID(chat_id=presence.user_id.chat_id,
                         gaia_id=presence.user_id.gaia_id)
            user = self.get_user(user_id)
            if user is not None:
                user.set_presence(presence.presence)
                yield from self.on_presence.fire(user, presence.presence)
            else:
                logger.warning('Received PresenceNotification for '
                               'unknown user {}'.format(user_id))