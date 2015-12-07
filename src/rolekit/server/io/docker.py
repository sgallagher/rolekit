# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
#
# Authors:
# Stephen Gallagher <sgallagh@redhat.com>
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

"""
Provides utility functions for working with Docker.io containers
"""

import docker
import docker.utils

PROTO_UDP = 'udp'
PROTO_TCP = 'tcp'

MODE_RW = 'rw'
MODE_RO = 'ro'
MODE_SHARED_VOLUME = 'z'
MODE_PRIVATE_VOLUME = 'Z'

class RolekitDockerPortBindings:
    def __init__(self):
        self._bindings = {}

    def add_binding(self,
                    container_port,
                    host_port,
                    protocol=None,
                    host_address=None):
        """
        Add a new port binding
        :param container_port: The port exposed by the internal service to
                                   the host.
        :param host_port: The port that will be exposed by the host to the
                              outside world.
        :param protocol: specify rolekit.server.io.docker.PROTO_UDP or
                         rolekit.server.io.docker.PROTO_TCP. Defaults to
                         PROTO_TCP
        :param host_address: Restrict this port binding to being exposed only
                             on certain host interfaces. Default: all
        :return: No error conditions
        """

        if not protocol:
            protocol = PROTO_TCP

        self._bindings["%s/%s" % (container_port, protocol)] = {
            'container_port': container_port,
            'host_port': host_port,
            'protocol': protocol,
            'host_address': host_address
        }

    @property
    def docker_ports(self):
        """
        Return the list of internal ports that Docker will need to be aware of
        :return: A list of tuples of the form (port, protocol)
        """

        return [ (self._bindings[x]['container_port'],
                  self._bindings[x]['protocol'])
                 for x in self._bindings ]

    @property
    def docker_bindings(self):
        """
        Return a dictionary of port bindings that Docker can use in
        create_host_config()
        :return: A dictionary of bindings in Docker's format
        """
        docker_bindings = {}

        for binding in self._bindings:
            if self._bindings[binding]['host_address']:
                docker_bindings[binding] = (self._bindings[binding]['host_port'],
                                            self._bindings[binding]['host_address'])
            else:
                docker_bindings[binding] = self._bindings[binding]['host_port']

        return docker_bindings

    @property
    def docker_cli_port_bindings(self):
        """
        :return: Arguments formatted for the '-p/--publish' arguments to
                `docker run`
        """
        docker_arguments = []

        for binding in self._bindings:
            if self._bindings[binding]['host_address']:
                docker_arguments.append("%s:%d:%s/%s" % (
                    self._bindings[binding]['host_address'],
                    self._bindings[binding]['host_port'],
                    self._bindings[binding]['container_port'],
                    self._bindings[binding]['protocol'],
                ))
            else:
                docker_arguments.append("%d:%s/%s" % (
                    self._bindings[binding]['host_port'],
                    self._bindings[binding]['container_port'],
                    self._bindings[binding]['protocol'],
                ))
        return docker_arguments

class RolekitDockerBindMounts:
    def __init__(self):
        self.bindings = {}

    def add_binding(self, host_path, container_path, mode):
        # We will store them in the same format that Docker expects
        self.bindings[host_path] = {
            'bind': container_path,
            'mode': mode
        }

    @property
    def docker_bindings(self):
        return self.bindings

    @property
    def docker_mounts(self):
        return [self.bindings[x]['bind'] for x in self.bindings]

    @property
    def docker_cli_bind_mounts(self):
        """
        :return: Arguments formatted for the '-v/--volume' arguments to
                 `docker run`
        """
        docker_arguments = []
        for binding in self.bindings:
            docker_arguments.append("%s:%s:%s" % (
                                        self.bindings[binding]['bind'],
                                        binding,
                                        self.bindings[binding]['mode']
                                    )
            )
        return docker_arguments