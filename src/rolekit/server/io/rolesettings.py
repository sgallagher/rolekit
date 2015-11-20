# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import errno
import shutil
import json

from rolekit.config import ETC_ROLEKIT_ROLES, ETC_ROLEKIT_DEFERREDROLES
from rolekit.config import NASCENT, ERROR, SYSTEMD
from rolekit.logger import log
from rolekit.util import validate_name


class RoleSettings(dict):
    """ Rolesettings store """

    def __init__(self, type_name, name, deferred=False, *args, **kwargs):
        super(RoleSettings, self).__init__(*args, **kwargs)

        # If name is given check it
        if name:
            validate_name(name)
        # Check type name
        validate_name(type_name)

        self._name = name
        self._type = type_name

        if deferred:
            self.path = "%s/%s" % (ETC_ROLEKIT_DEFERREDROLES, self.get_type())
        else:
            self.path = "%s/%s" % (ETC_ROLEKIT_ROLES, self.get_type())

        # Ensure that this directory exists
        try:
            os.makedirs(self.path)
        except OSError as e:
            if e.errno == errno.EEXIST:
                if not os.path.isdir(self.path):
                    log.fatal("'%s' is not a directory.", e.strerror)
            else:
                log.fatal("Failed to create '%s': %s", e.strerror)
                raise
        else:
            log.debug1("Created missing '%s'.", self.path)

        # If we need to autogenerate a name, do it here
        if not name:
            # Check both the existing and deferred role directories
            self._name = self.get_unique_instance(self.get_type())

        self.filepath = "%s/%s.json" % (self.path, self.get_name())
        self._callbacks = { "changed": None }

    def get_name(self):
        return self._name

    def get_type(self):
        return self._type

    def connect(self, signal, handler, *args):
        """Connect a callback to the given signal with optional user data.

        :param str signal:
            The signal to connect to, right now only "changed" is supported.
        :param callable handler:
            Callback handler to connect the signal to.
        :param *args:
            Variable data which is passed through to the signal handler.

        The "changed" signal:
            user_function(property, new_value[, *args])
        """
        if signal in self._callbacks:
            self._callbacks[signal] = (handler, args)
        else:
            raise ValueError("Unknown signal name '%s'" % signal)

    def __setitem__(self, key, value):
        """Set item in RoleSettings and call the handler the changed signal
        if set.

        :param str key:
            The name of the property to be changed.
        :param value:
            Variable value data the property will be set to.
        """
        super(RoleSettings, self).__setitem__(key, value)
        # call callback
        if "changed" in self._callbacks and self._callbacks["changed"]:
            cb = self._callbacks["changed"]
            cb_args = [ key, value ]
            try:
                cb_args.extend(cb[1])
            except TypeError:
                # Got None here
                pass
            try:
                # call back
                cb[0](*cb_args)
            except Exception as msg:
                print(msg)

    def read(self):
        with open(self.filepath, "r") as f:
            data = f.read()
        imported = json.loads(data)
        del data
        if type(imported) is not dict:
            return

        for key,value in imported.items():
            self[key] = value
        del imported

        # Every time we read this file in, we need to update the role status
        # with the actual state of the target unit. We will do that in
        # rolebase.py; for now we set the state to SYSTEMD to indicate that
        # it has not yet been updated.
        # If there is no state here, it is because this role is not yet
        # deployed.
        if "state" not in self:
            self["state"] = NASCENT
        elif self["state"] == ERROR or self["state"] == NASCENT:
            # Do not change the state if we are in ERROR or NASCENT
            # We don't want to reset this from systemd. In the ERROR case,
            # this might result in losing the error data. In the NASCENT
            # case, we would end up getting an error trying to retrieve a
            # non-existent systemd unit state.
            pass
        else:
            # Note: this should never get written out to the JSON settings
            # file. It will always be updated immediately by roled when
            # appropriate.
            self["state"] = SYSTEMD


    def backup(self):
        try:
            os.mkdir(self.path)
        except OSError:
            pass

        try:
            shutil.copy2(self.filepath, "%s.old" % self.filepath)
        except Exception as msg:
            if os.path.exists(self.filepath):
                raise IOError("Backup of '%s' failed: %s" % (self.filepath,
                                                             msg))

    def write(self):
        self.backup()
        d = json.dumps(self)

        # Settings files may contain sensitive information,
        # so we'll restrict access to them to the rolekit user
        # (generally 'root')
        old_umask = os.umask(0o0177)
        with open(self.filepath, "w") as f:
            f.write(d)
        os.umask(old_umask)

    def remove(self):
        try:
            self.backup()
        except Exception as msg:
            log.error(msg)

        try:
            os.remove(self.filepath)
        except OSError:
            pass

    @staticmethod
    def get_instances(type):
        instances = [ ]
        for path in ("%s/%s" % (ETC_ROLEKIT_ROLES, type),
                     "%s/%s" % (ETC_ROLEKIT_DEFERREDROLES, type)):
            if os.path.exists(path) and os.path.isdir(path):
                for name in sorted(os.listdir(path)):
                    if not name.endswith(".json"):
                        continue
                    # Add this instance to the list, sans .json
                    instances.append(name[:-5])
        return instances

    @staticmethod
    def get_unique_instance(type):
        # We'll use numeric identifiers for instances
        id = 1
        while str(id) in RoleSettings.get_instances(type):
            id += 1
        log.debug1("Generating unique instance %s" % str(id))
        return str(id)
