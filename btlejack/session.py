"""
Bluetooth Low Energy session.
"""

import os
import json
from time import time

class BtlejackSessionError(Exception):
    def __init__(self):
        super().__init__(self)

class BtlejackSession:
    """
    Btlejack user session class

    This class provides some primitives to keep track of sessions, in the user
    directory (~/.btlejack/).
    """

    instance = None

    def __init__(self):
        """
        Compute session file path and initialize sessions array.
        """
        # ensure the directory exists
        self._session_dir = os.path.join(
            os.path.expanduser('~'),
            '.btlejack',
        )
        if not os.path.exists(self._session_dir):
            try:
                os.mkdir(self._session_dir)
            except:
                raise BtlejackSessionError()
        elif not os.path.isdir(self._session_dir):
            raise BtlejackSessionError()

        self._session_path = os.path.join(
            os.path.expanduser('~'),
            '.btlejack',
            'sessions'
        )

        self.connections = {}


    def add_connection(self, access_address, parameters):
        """
        Add or update an existing BLE connection to this session.
        """
        if access_address in self.connections:
            for key in parameters:
                self.connections[access_address][key] = parameters[key]
        else:
            self.connections[access_address] = parameters
            self.connections[access_address]['start'] = int(time())

    def find_connection(self, access_address):
        """
        Search an existing connection.
        """
        if str(access_address) in self.connections:
            return self.connections[str(access_address)]
        return None

    def remove_connection(self, access_address):
        """
        Remove a given connection from the session.
        """
        if access_address in self.connections:
            del self.connections[access_address]

    def clear(self):
        """
        Clear current session.
        """
        self.connections={}
        self.save()

    def load(self):
        """
        Load user' session.

        @return bool True if loading successfully, False otherwise.
        """
        try:
            session = open(self._session_path, 'r')
            self.connections = json.load(session)
            session.close()
            return True
        except IOError as exc:
            return False

    def save(self):
        """
        Save current sessions as JSON.
        """
        sessionfile = open(self._session_path, 'w')
        json.dump(self.connections, sessionfile)
        sessionfile.close()


    @staticmethod
    def get_instance():
        if BtlejackSession.instance is None:
            BtlejackSession.instance = BtlejackSession()
        return BtlejackSession.instance
