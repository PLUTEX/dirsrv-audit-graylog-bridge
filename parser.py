import logging
from collections import defaultdict


class InvalidLineError(Exception):
    pass


class AuditLogParser:
    """
    Parser for 389-ds LDAP Audit Log.

    :param fd: The opened audit log file object
    :param cb: The callback that is called for every block of changes
    """

    logger = logging.getLogger('AuditLogParser')

    def __init__(self, cb):
        """
        Initialize parser with callback function

        :param cb: callback function
        """
        self.cb = cb
        self.change_block = defaultdict(list)
        self._last_key = None

    def call_cb(self):
        try:
            self.cb(dict(self.change_block))
        except Exception:
            self.logger.exception("Exception during callback")

    def parse_line(self, line):
        """
        Parse one line from the audit log.

        :param line: Single line as string
        """

        line = line.rstrip('\r\n')

        if line == '':
            # An empty line terminates the change block.
            # Call the callback end reset instance state.
            self.call_cb()
            self.change_block = defaultdict(list)
            self._last_key = None

        elif line.startswith(' '):
            # Continuation of previous line starts with a single space
            self.change_block[self._last_key][-1] += line[1:]

        elif line != '-':
            # Usual lines have the format
            #     key: value
            try:
                key, val = line.split(': ', 1)
            except ValueError:
                raise InvalidLineError()

            # Binary values can be base64-encoded, in which case the format is
            #     key:: value
            # We don't care about the encoding, as we need to report a string
            # anyway, so simply strip the extra colon
            key = key.rstrip(':').lower()

            self.change_block[key].append(val)
            self._last_key = key

    def parse_file(self, fd):
        """
        Parse the whole audit log file and call the callback for each block of
        changes.

        :param fd: opened log file object
        :returns: True if the last change block was unterminated, in which case
                  calling `call_cb` might make sense. False otherwise.
        """
        while True:
            line = fd.readline()
            if line == '':
                # emptry reply from readline means EOF
                break

            self.parse_line(line)

        return bool(self.change_block)
