"""
Support for TECHNICOLOR routers via SSH.
For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.technicolor_ssh/
"""
import logging
import re
import paramiko

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (
    CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PORT)

_LOGGER = logging.getLogger(__name__)

_DEVICES_REGEX = re.compile(
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s+'
    r'(?P<type>([^\s]+))\s+(?P<intf>([^\s]+))\s+'
    r'(?P<hwintf>([^\s]+))\s+'
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s+'
    r'(?P<status>([^\s]+))')

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
    vol.Required(CONF_PORT): cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return a TECHNICOLOR scanner."""
    scanner = TechnicolorSSHDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


class TechnicolorSSHDeviceScanner(DeviceScanner):

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.port = config[CONF_PORT]
        self.last_results = {}

        # Test the router is accessible.
        data = self.get_technicolor_data()
        self.success_init = data is not None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [client['mac'] for client in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if not self.last_results:
            return None
        for client in self.last_results:
            if client['mac'] == device:
                return client['host']
        return None

    def _update_info(self):
        """Ensure the information from the TECHNICOLOR router is up to date.
        Return boolean if scanning successful.
        """
        if not self.success_init:
            return False

        # _LOGGER.info("Checking ARP")
        data = self.get_technicolor_data()
        if not data:
            return False

        # Flag C stands for CONNECTED
        active_clients = [client for client in data.values() if
                          client['status'] == 'REACHABLE']
        self.last_results = active_clients
        print(active_clients)
        return True

    def get_technicolor_data(self):
        """Retrieve data from TECHNICOLOR and return parsed result."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=self.host,
                        username=self.username,
                        password=self.password,
                        port=self.port)
            stdin, stdout, stderr = ssh.exec_command("ip niegh")

            if stderr.read().decode('UTF-8'):
                raise ValueError

            devices_result = [x.strip() for x in stdout.readlines()]
            ssh.close()

        except ValueError:
            _LOGGER.exception("Unexpected response from router")
            return
        except TimeoutError:
            _LOGGER.exception("Router did not respond")
            return
        except paramiko.ssh_exception.AuthenticationException:
            _LOGGER.exception(
                "Authentication error, correct username and password?")
            _LOGGER.exception("Unexpected response from router")
            return
        except ConnectionRefusedError:
            _LOGGER.exception(
                "Connection refused by router. SSH enabled?")
            return

        devices = {}
        for device in devices_result:
            match = _DEVICES_REGEX.search(device)
            if match:
                devices[match.group('ip')] = {
                    'ip': match.group('ip'),
                    'mac': match.group('mac').upper(),
                    'host': self.host,
                    'status': match.group('status')}
        return devices
