# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Red Hat, Inc.
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

import dbus
import dbus.service
import socket
import string
import os
import random
import re
import json

from rolekit.logger import log
from rolekit.server.rolebase import RoleBase
from rolekit.server.rolebase import RoleDeploymentValues
from rolekit.server.io.hostname import set_hostname
from rolekit.server.io.systemd import enable_units
from rolekit.server.io.systemd import SystemdUnitParser
from rolekit.errors import COMMAND_FAILED, INVALID_PROPERTY
from rolekit.errors import INVALID_VALUE, UNKNOWN_ERROR
from rolekit.errors import MISSING_CHECK, RolekitError
from rolekit.util import generate_password
from rolekit.dbus_utils import SystemdJobHandler
from rolekit.config import SYSTEMD_UNITS
from IPy import IP

INSTALL_ARG_FILENAME="ipa-server-install-options"

FREEIPA_DOCKER_IMAGE = "sgallagh/freeipa-server"
FREEIPA_DOCKER_TAG = "latest"

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        "version": 1,
        "services": [ ],
        "packages": [ "docker",
                      "python3-docker-py",
                    ],
        "firewall": { "ports": [ ],
                     "services": [ "freeipa-ldap",
                                   "freeipa-ldaps",
                                   "dns" ] },

        # Host name will use the current system name if unspecified
        # If the system name starts with "localhost" it will be changed to
        # DC-<UUID>
        "host_name": None,

        # Default domain name will be autodetected if not specified
        "domain_name": None,

        # do_deploy_async() will check whether this is set and make it
        # the upper-case version of domain_name if not.
        "realm_name": None,

        # If not supplied, do_deploy_async() will generate a
        # random password
        "admin_password": None,

        # If not supplied, do_deploy_async() will generate a
        # random password
        "dm_password": None,

        # Location on local machine to store persistent IPA data
        "data_dir": "/var/lib/ipa-data",

        # Starting ID value for the domain
        # If unset, will be assigned randomly
        # If set, id_max must also be set
        "id_start": None,

        # Highest ID value for the domain
        # If unset, the domain will have space
        # for 200,000 IDs (FreeIPA default).
        # If set, id_start must also be set
        "id_max": None,

        # Path to a root CA certificate
        # If not specified, one will be generated
        "root_ca_file": None,

        # Install DNS Server
        "serve_dns": True,

        # Set up the DNS reverse zone
        "reverse_zone": None,

        # Primary IP address of the machine
        # This is necessary when setting up DNS
        # to work around
        # https://fedorahosted.org/freeipa/ticket/3575
        "primary_ip": None,

        # DNS Forwarders
        # If unspecified, installation will default to root servers
        # Otherwise, it should be a dictionary of lists of IP Addresses
        # as below:
        # "dns_forwarders": {"ipv4": [
        #                            "198.41.0.4",  # a.root-servers.net
        #                            "192.228.79.201",  # b.root-servers.net
        #                            "192.33.4.12"],  # c.root-servers.net
        #                   "ipv6": [
        #                            "2001:500:2d::d",  # d.root-servers.net
        #                            "2001:500:2f::f",  # f.root-servers.net
        #                            "2001:500:1::803f:235",  # h.root-servers.net
        #                           ]
        #                  },
        "dns_forwarders": None,

        # ID of the container to be created
        # This must not be set by the caller.
        "container_id": None,

        # TODO: There are many less-common options to ipa-server-install.
        # The API should support them.
    })

    # Use _READONLY_SETTINGS from RoleBase and add new if needed.
    # Without new readonly settings, this can be omitted.
    # _READONLY_SETTINGS = RoleBase._READONLY_SETTINGS + []

    # maximum number of instances of this role
    _MAX_INSTANCES = 1


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)

        # Add a compiled regular expression for testing domain validity
        self.allowed_fqdn = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        log.debug9("TRACE: do_deploy_async")
        # Do the magic
        #
        # In case of error raise an exception

        # Make sure that they didn't try to assign the container_id
        if "container_id" in values:
            raise RolekitError(INVALID_PROPERTY,
                               "container_id is not user-selectable.")

        import docker
        from rolekit.server.io.docker import RolekitDockerPortBindings, \
                                             PROTO_TCP, PROTO_UDP
        from rolekit.server.io.docker import RolekitDockerBindMounts, \
                                             MODE_PRIVATE_VOLUME

        # Get the domain name from the passed-in settings
        # or set it to the instance name if ommitted

        if 'domain_name' not in values:
            values['domain_name'] = self.get_name()

        if not self._valid_fqdn(values['domain_name']):
            raise RolekitError(INVALID_VALUE,
                               "Invalid domain name: %s" % values['domain_name'])

        if "host_name" not in values:
            # Let's construct a new host name.
            host_part = self._get_hostname()
            if host_part.startswith("localhost"):
                # We'll assign a random hostname starting with "dc-"
                random_part = ''.join(random.choice(string.ascii_lowercase)
                                      for _ in range(16))
                host_part = "dc-%s" % random_part

            values['host_name'] = "%s.%s" % (host_part, values['domain_name'])

        if not self._valid_fqdn(values['host_name']):
            raise RolekitError(INVALID_VALUE,
                               "Invalid host name: %s" % values['host_name'])

        # Change the hostname with the hostnamectl API
        yield set_hostname(values['host_name'])

        # If left unspecified, default the realm to the
        # upper-case version of the domain name
        if 'realm_name' not in values:
            values['realm_name'] = values['domain_name'].upper()

        # If left unspecified, assign a random password for
        # the administrative user
        if 'admin_password' not in values:
            admin_pw_provided = False
            values['admin_password'] = generate_password()
        else:
            admin_pw_provided = True

        # If left unspecified, assign a random password for
        # the directory manager
        if 'dm_password' not in values:
            dm_pw_provided = False
            values['dm_password'] = generate_password()
        else:
            dm_pw_provided = True

        # Call ipa-server-install with the requested arguments
        ipa_install_args = [
                '-r', values['realm_name'],
                '-d', values['domain_name'],
                '-p', values['dm_password'],
                '-a', values['admin_password'],
            ]

        # If the user has requested the DNS server, enable it
        if 'serve_dns' not in values:
            values['serve_dns'] = self._settings['serve_dns']

        if values['serve_dns']:
            ipa_install_args.append('--setup-dns')

            # Pass the primary IP address
            if 'primary_ip' in values:
                ipa_install_args.append('--ip-address=%s' %
                                        values['primary_ip'])

            # if the user has requested DNS forwarders, add them
            if 'dns_forwarders' in values:
                [ipa_install_args.append("--forwarder=%s" % x)
                     for x in values['dns_forwarders']['ipv4']]
                [ipa_install_args.append("--forwarder=%s" % x)
                     for x in values['dns_forwarders']['ipv6']]
            else:
                ipa_install_args.append('--no-forwarders')

            # If the user has requested the reverse zone add it
            if 'reverse_zone' in values:
                for zone in values['reverse_zone']:
                    ipa_install_args.append('--reverse-zone=%s' % zone)
            else:
                ipa_install_args.append('--no-reverse')

        # If the user has requested a specified ID range,
        # set up the argument to ipa-server-install
        if 'id_start' in values or 'id_max' in values:
            if ('id_start' not in values or
                'id_max' not in values or
                not values['id_start'] or
                not values['id_max']):

                raise RolekitError(INVALID_VALUE,
                                   "Must specify id_start and id_max together")

            if (values['id_start'] and values['id_max'] <= values['id_start']):
                raise RolekitError(INVALID_VALUE,
                                   "id_max must be greater than id_start")

            ipa_install_args.append('--idstart=%d' % values['id_start'])
            ipa_install_args.append('--idmax=%d' % values['id_max'])

        # TODO: If the user has specified a root CA file,
        # set up the argument to ipa-server-install

        # Construct the `ipa-server-install-options file for the container
        log.debug2("Generating install directive file")

        # Create the persistent data directory, if needed
        if 'data_dir' not in values:
            values['data_dir'] = self._settings['data_dir']
        try:
            os.mkdir(values["data_dir"])
        except FileExistsError:
            # The directory already exists, so we'll attempt to use it
            # First we need to make sure that it's not already configured.
            if os.path.exists(os.path.join(values['data_dir'],
                                           'etc', 'ipa',
                                           'ca.crt')):
                raise RolekitError(UNKNOWN_ERROR,
                                   "%s was previously configured. Please "
                                   "move or delete directory contents and "
                                   "try again." % values['data_dir'])

            pass
        except PermissionError:
            log.error("Could not create %s" % values["data_dir"])
            raise

        install_arg_file = os.path.join(values["data_dir"],
                                        INSTALL_ARG_FILENAME)
        try:
            old_umask = os.umask(0o0177)
            with open(install_arg_file, "w") as f:
                for argument in ipa_install_args:
                    f.write("%s\n" % argument)
            os.umask(old_umask)
        except PermissionError:
            log.error("Could not write to %s" % install_arg_file)
            raise

        # Remove the passwords from the values so
        # they won't be saved to the settings
        if admin_pw_provided:
            values.pop('admin_password', None)
        if dm_pw_provided:
            values.pop('dm_password', None)

        # Create a container for FreeIPA and launch that
        log.debug2("Enabling the Docker container manager")

        # Enable and start the docker service
        enable_units(['docker.service'])

        log.debug2("Starting the Docker container manager")
        with SystemdJobHandler() as job_handler:
            job_path = job_handler.manager.StartUnit("docker.service", "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()
            if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                details = ", ".join(["%s: %s" % item for item in job_results.items()])
                raise RolekitError(COMMAND_FAILED, "Starting docker.service failed: %s" % details)

        log.debug2("Pulling %s image from Docker Hub" % FREEIPA_DOCKER_IMAGE)
        dockerclient = docker.Client(base_url=docker.utils.utils.DEFAULT_UNIX_SOCKET,
                                     version='auto')

        # First, pull down the latest version of the FreeIPA container
        # TODO: get the appropriate tag from /etc/os-release
        for line in dockerclient.pull(repository=FREEIPA_DOCKER_IMAGE,
                                      tag=FREEIPA_DOCKER_TAG,
                                      stream=True):
            msg = json.loads(line.decode('utf8'))
            log.debug9("RAW: %s" % repr(msg))
            if "stream" in msg:
                log.info1("STREAM: %s" % msg["stream"])

        # Always print the last message
        if "status" in msg:
            log.info1("%s", msg["status"])

        # Set up the port bindings
        port_bindings = RolekitDockerPortBindings()

        port_bindings.add_binding(80, 80, PROTO_TCP)     # HTTP
        port_bindings.add_binding(88, 88, PROTO_TCP)     # Kerberos
        port_bindings.add_binding(88, 88, PROTO_UDP)     # Kerberos
        port_bindings.add_binding(123, 123, PROTO_TCP)   # NTP
        port_bindings.add_binding(389, 389, PROTO_TCP)   # LDAP[TLS]
        port_bindings.add_binding(443, 443, PROTO_TCP)   # HTTPS
        port_bindings.add_binding(464, 464, PROTO_TCP)   # Ketberos
        port_bindings.add_binding(464, 464, PROTO_UDP)   # Kerberos
        port_bindings.add_binding(636, 636, PROTO_TCP)   # LDAPS
        port_bindings.add_binding(7389, 7389, PROTO_TCP) # LDAP Replication
        port_bindings.add_binding(9443, 9443, PROTO_TCP) # Dogtag
        port_bindings.add_binding(9444, 9444, PROTO_TCP) # Dogtag
        port_bindings.add_binding(9445, 9445, PROTO_TCP) # Dogtag

        if values["serve_dns"]:
            port_bindings.add_binding(53, 53, PROTO_TCP) #DNS
            port_bindings.add_binding(53, 53, PROTO_UDP) #DNS

        # Add the mount point for the persistent data
        bind_mounts = RolekitDockerBindMounts()
        bind_mounts.add_binding(host_path=values['data_dir'],
                                container_path='/data',
                                mode=MODE_PRIVATE_VOLUME)

        # Set a special environment variable to have the initialization
        # return after completing.
        env_vars = {
            "JUST_INIT": "1"
        }

        # Also specify the primary IPA server IP if it was provided
        if "primary_ip" in values:
            env_vars["IPA_SERVER_IP"] = str(values["primary_ip"])

        # Launch the container once to do the initial setup.
        log.info1("Starting container")
        container = dockerclient.create_container(
            image="%s:%s" % (FREEIPA_DOCKER_IMAGE, FREEIPA_DOCKER_TAG),
            name="rolekit_freeipa_%s" % self.get_name(),
            hostname=values['host_name'],
            environment=env_vars,
            ports=port_bindings.docker_ports,
            volumes=bind_mounts.docker_mounts,
            host_config=docker.utils.create_host_config(
                port_bindings=port_bindings.docker_bindings,
                binds=bind_mounts.docker_bindings
            ),
            detach=True
        )
        values['container_id'] = container.get('Id')
        dockerclient.start(values['container_id'])

        # Monitor and record the logs for the setup
        for line in dockerclient.logs(container=container,
                                      stream=True,
                                      stderr=True,
                                      stdout=True,
                                      timestamps=True):
            log.debug9("%s" % line)

        # Check the return code
        result = dockerclient.wait(container)
        log.info1("Starting container completed: %d", result)
        if result != 0:
            # Remove this container
            # REMOVEME: uncomment this before pushing
            # dockerclient.remove_container(container=container,
            #                               force=True)

            # Something went wrong, return an error
            raise RolekitError(COMMAND_FAILED, "%d" % result)

        log.debug2("Creating systemd service unit")
        # Generate a systemd service unit for this container
        unitfile = SystemdUnitParser()

        # == Create the [Unit] Section == #
        unitfile['Unit'] = {}
        unitfile['Unit']['Description'] =\
            "FreeIPA docker container - %s" % self.get_name()

        unitfile['Unit']['Requires'] = "docker.service"
        unitfile['Unit']['After'] = "docker.service"
        unitfile['Unit']['BindsTo'] = "docker.service"

        # == Create the [Service] Section == #
        unitfile['Service'] = {}
        unitfile['Service']['Type'] = 'simple'
        unitfile['Service']['ExecStart'] = '/usr/bin/docker start '\
                                            '--attach=true %s' % \
                                           (values['container_id'])
        unitfile['Service']['ExecStop'] = '/usr/bin/docker stop -t 5 %s' % \
                                           (values['container_id'])

        with open(os.path.join(SYSTEMD_UNITS, "freeipa_%s.service" % self.get_name()), 'w') as configfile:
            unitfile.write(configfile)

        # Make systemd load this new unit file
        log.debug2("Running systemd daemon-reload")
        with SystemdJobHandler() as job_handler:
            job_handler.manager.Reload()

        # Create the systemd target definition
        target = RoleDeploymentValues(self.get_type(), self.get_name(),
                                      "Domain Controller")
        target.add_required_units(['freeipa_%s.service' % self.get_name()])

        log.debug9("TRACE: exiting do_deploy_async")
        # We're done!
        yield target


    # Redeploy code
    def do_redeploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        raise NotImplementedError("Redeploy not supported yet")


    def do_decommission_async(self, force=False, sender=None):
        import docker

        # Remove the container unit
        log.info1("Removing container unit")
        path = "%s/freeipa_%s.service" % (SYSTEMD_UNITS, self.get_name())
        try:
            os.unlink(path)
        except FileNotFoundError:
            # If the file wasn't there, this is probably part of a
            # redeploy fixing a failed initial deployment.
            pass

        # Remove the Docker container
        log.info1("Removing Docker container")
        dockerclient = docker.Client(base_url=docker.utils.utils.DEFAULT_UNIX_SOCKET,
                             version='auto')

        try:
            dockerclient.remove_container(container=self._settings['container_id'],
                                          force=True)
        except:
            log.error("Could not remove Docker container! Manual "
                      "intervention required. Proceeding with decommission.")

        # TODO: Clean up the data_dir as well
        # TAR up the current contents and remove them
        log.info1("WARNING! %s has not been altered. Back it up and remove "
                 "it before attempting to deploy again from the same "
                 "location." % self._settings['data_dir'])

        yield None

    # Update code
    def do_update_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        raise NotImplementedError()


    # Check own properties
    def do_check_property(self, prop, value):
        if prop in [ "realm_name",
                     "container_id" ]:
            return self.check_type_string(value)

        elif prop in [ "admin_password",
                       "dm_password" ]:
            self.check_type_string(value)

            if len(value) < 8:
                raise RolekitError(INVALID_VALUE,
                                   "{0} must be at least eight characters"
                                   .format(prop))
            return True

        elif prop in [ "host_name" ]:
            self.check_type_string(value)

            if not self._valid_fqdn(value):
                raise RolekitError(INVALID_VALUE,
                                   "Invalid hostname: %s" % value)

            return True

        elif prop in [ "domain_name" ]:
            self.check_type_string(value)

            if not self._valid_fqdn(value):
                raise RolekitError(INVALID_VALUE,
                                   "Invalid domain name: %s" % value)

            return True

        elif prop in [ "root_ca_file" ]:
            self.check_type_string(value)

            if not os.path.isfile(value):
                raise RolekitError(INVALID_VALUE,
                                   "{0} is not a valid CA file"
                                   .format(value))
            return True

        elif prop in [ "data_dir" ]:
            self.check_type_string(value)

            if os.path.exists(value) and not os.path.isdir(value):
                raise RolekitError(INVALID_VALUE,
                                   "{0} exists and is not a directory"
                                   .format(value))
            return True

        if prop in [ "reverse_zone" ]:
            # TODO: properly parse reverse zones here
            # Getting this right is very complex and
            # FreeIPA already does it internally.
            return self.check_type_string_list(value)

        elif prop in [ "serve_dns" ]:
            return self.check_type_bool(value)

        elif prop in [ "id_start",
                       "id_max" ]:
            return self.check_type_int(value)

        elif prop in [ "dns_forwarders" ]:
            self.check_type_dict(value)
            for family in value.keys():
                self.check_type_string(family)

                if family not in [ "ipv4", "ipv6" ]:
                    raise RolekitError(INVALID_VALUE,
                                       "{0} is not a supported IP family"
                                       .format(family))

                self.check_type_string_list(value[family])

                for address in value[family]:
                    try:
                        IP(address)
                    except ValueError as ve:
                        raise RolekitError(INVALID_VALUE,
                                           "{0} is not a valid IP address"
                                           .format(address))
            return True

        elif prop in [ "primary_ip" ]:
            try:
                IP(value)
            except ValueError as ve:
                raise RolekitError(INVALID_VALUE,
                        "{} is not a valid IP address: {}".format(value, ve))
            return True

        # We didn't recognize this argument
        return False


    # Sanitize settings
    def do_sanitize(self):
        """Sanitize settings"""
        self._settings['admin_password'] = None
        self._settings['dm_password'] = None


    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.do_get_dbus_property(<class>, key)
    #   Returns settings as dbus types
    #
    # Usage in instances: role.do_get_dbus_property(role, key)
    #   Uses role.get_property(role, key)
    #
    # This method needs to be extended for new role settings.
    # Without additional properties, this can be omitted.
    @staticmethod
    def do_get_dbus_property(x, prop):
        # Cover additional settings and return a proper dbus type.
        if prop in [ "domain_name",
                     "realm_name",
                     "host_name",
                     "admin_password",
                     "dm_password",
                     "root_ca_file",
                     "data_dir",
                     "primary_ip",
                     "container_id"]:
            return dbus.String(x.get_property(x, prop))
        elif prop in [ "reverse_zone" ]:
            return dbus.Array(x.get_property(x, prop), "s")
        elif prop in [ "serve_dns" ]:
            return dbus.Boolean(x.get_property(x, prop))
        elif prop in [ "id_start",
                       "id_max" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "dns_forwarders" ]:
            return dbus.Dictionary(x.get_property(x, prop), "sas")

        raise RolekitError(INVALID_PROPERTY, prop)

    # Helper Routines
    def _get_hostname(self):
        # First, look up this machine's hostname
        # We don't need the FQDN because we're only interested
        # in the first part anyway.
        host = socket.gethostname()

        # Get everything up to the first dot as the hostname
        return host.split(".")[0]


    # Check Domain Controller-specific properties
    def _check_property(self, prop, value):
        try:
            super(Role, self)._check_property(prop, value)
        except RolekitError as e:
            if e.code == MISSING_CHECK:
                log.debug1("Unvalidated property: %s" % prop)
            else:
                log.debug1("Property %s did not validate" % prop)
                raise

    def _valid_fqdn(self, fqdn):
        # Most parts taken from
        # http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        # This function will also work for either domain or hostname-only
        # portions of a hostname
        if len(fqdn) > 255:
            return False

        # Disallow the autogenerated instance names (names that are nothing but
        # a number)
        if fqdn.isdigit():
            return False

        if fqdn[-1] == ".":
            fqdn = fqdn[:-1] # strip exactly one dot from the right, if present

        return all(self.allowed_fqdn.match(x) for x in fqdn.split("."))
