import os.path
import socket
import warnings
import re

from acmems.auth import Authenticator


class ConfigurationError(Exception):
    pass


class MissingSectionError(ConfigurationError):
    pass


class UnknownVerificationError(ConfigurationError):
    pass


class UnknownStorageError(ConfigurationError):
    pass


class SingletonOptionRedifined(ConfigurationError):
    def __init__(self, section, option, old, new):
        self.section = section
        self.option = option
        self.old = old
        self.new = new

    def __str__(self):
        return 'Singleton option redefined: {}.{} was {}, redefined as {}'.format(self.section, self.option, self.old, self.new)


class ConfigurationWarning(UserWarning):
    pass


class UnusedOptionWarning(ConfigurationWarning):
    pass


class OptionRedifinitionWarning(ConfigurationWarning):
    pass


class UnusedSectionWarning(ConfigurationWarning):
    pass


class Configurator():
    def __init__(self, *configs):
        self.validators = {}
        self.default_validator = None
        self.storages = {}
        self.default_storage = None
        self._max_size = None

        self.auth = Authenticator(self)
        for config in configs:
            self.parse(config)

    @property
    def keyfile(self):
        return os.path.join(self.account_dir, 'account.pem')

    @property
    def registration_file(self):
        return os.path.join(self.account_dir, 'registration.json')

    @property
    def max_size(self):
        return self._max_size or 4096

    def parse(self, config):
        config = self.read_data(config)
        self.parse_account_config(config.pop('account'))
        self.parser_mgmt_config(config.pop('mgmt'))
        special_group_re = re.compile('^(?P<type>(auth|verification|storage)) (?P<opener>"?)(?P<name>.+)(?P=opener)$')
        auth_blocks = []
        for group, options in config.items():
            match = special_group_re.match(group)
            if match:
                if match.group('type') == 'auth':
                    # parse auth blocks last to have verification and storage blocks processed
                    auth_blocks.append((match.group('name'), options))
                elif match.group('type') == 'verification':
                    self.parse_verification_group(match.group('name'), options)
                else:
                    self.parse_storage_group(match.group('name'), options)
            else:
                warnings.warn('Unknown section name: {0}'.format(group),
                              UnusedSectionWarning, stacklevel=2)

        self.setup_default_validator()
        self.setup_default_storage()

        for name, options in auth_blocks:
            self.auth.parse_block(name, options)

    @staticmethod
    def read_data(config):
        """ Reads the given file name. It assumes that the file has a INI file
            syntax. The parser returns the data without comments and fill
            characters. It supports multiple option with the same name per
            section but not multiple sections with the same name.

            :param str filename: path to INI file
            :return: a dictionary - the key is the section name value, the
                option is a array of (option name, option value) tuples"""
        sections = {}
        with config as f:
            section = None
            options = None
            for line in f:
                line = line.strip()
                # ignore comments:
                if line.startswith('#') or line.startswith(';'):
                    continue
                if not line:
                    continue
                # handle section header:
                if line.startswith('[') and line.endswith(']'):
                    if section:  # save old section data
                        sections[section] = options
                    section = line[1:-1]
                    options = []
                    continue
                if section is None:
                    warnings.warn('Option without sections: {0}'.format(line),
                                  UnusedOptionWarning, stacklevel=2)
                    continue
                option, value = line.split('=', 1)
                options.append((option.strip(), value.strip()))
            if section:  # save old section data
                sections[section] = options
        return sections

    def parse_account_config(self, config):
        self.acme_server = None
        for option, value in config:
            if option == 'acme-server':
                if self.acme_server is not None:
                    raise SingletonOptionRedifined(
                        section='account',
                        option='acme_server',
                        old=self.acme_server,
                        new=value)
                self.acme_server = value
            elif option == 'dir':
                self.account_dir = value
            else:
                warnings.warn('Option unknown [{}]{} = {}'.format('account', option, value),
                              UnusedOptionWarning, stacklevel=2)
        if self.acme_server is None:
            self.acme_server = 'https://acme-staging.api.letsencrypt.org/directory'

    def parser_mgmt_config(self, config):
        self.mgmt_listeners = None
        for option, value in config:
            if option == 'max-size':
                suffixes = {'k': 1024, 'm': 1024*1024}
                for suffix, mul in suffixes.items():
                    if value.endswith(suffix):
                        self._max_size = int(value[:len(suffix)]) * mul
                        break
                else:
                    self._max_size = int(value)
            elif option == 'default-verification':
                if value == '':
                    self.default_validator = False
                else:
                    self.default_validator = value.strip()
            elif option == 'default-storage':
                if value == '':
                    self.default_storage = False
                else:
                    self.default_storage = value.strip()
            elif option == 'listener':
                if self.mgmt_listeners is None:
                    self.mgmt_listeners = []
                if value == '':  # disable listener
                    continue
                if ':' not in value:
                    raise ConfigurationError('unix socket are currenlty not supported as listeners')
                host, port = value.rsplit(':', 1)
                if host[0] == '[' and host[-1] == ']':
                    host = host[1:-1]
                self.mgmt_listeners += socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
            else:
                warnings.warn('Option unknown [{}]{} = {}'.format('listeners', option, value),
                              UnusedOptionWarning, stacklevel=2)
        if self.mgmt_listeners is None:
            self.mgmt_listeners = socket.getaddrinfo('127.0.0.1', 1313, proto=socket.IPPROTO_TCP) \
                + socket.getaddrinfo('::1', 1313, proto=socket.IPPROTO_TCP)

    def parse_verification_group(self, name, options):
        option, value = options.pop(0)
        if option != 'type':
            raise ConfigurationError('A verification must start with the type value!')
        from acmems.challenges import setup
        self.validators[name] = setup(value, name, options)

    def setup_default_validator(self):
        if self.default_validator is False:  # default validator disabled
            return
        if self.default_validator:  # defined
            self.default_validator = self.validators[self.default_validator]
            return
        if len(self.validators) == 1:  # we use the only defined validator as default
            self.default_validator = list(self.validators.values())[0]
        else:  # define a default http storage
            from acmems.challenges import setup
            self.default_validator = self.validators['http'] = setup('http01', 'http', ())

    def parse_storage_group(self, name, options):
        option, value = options.pop(0)
        if option != 'type':
            raise ConfigurationError('A storage must start with the type value!')
        from acmems.storages import setup
        self.storages[name] = setup(value, name, options)

    def setup_default_storage(self):
        if self.default_storage is False:  # default storage disabled
            return
        if self.default_storage:
            self.default_storage = self.storages[self.default_storage]
        if len(self.storages) == 1:
            self.default_storage = list(self.storages.values())[0]
        else:
            from acmems.storages import setup
            self.default_storage = self.storages['none'] = setup('none', 'none', ())
