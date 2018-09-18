import logging
import json

from .catcherexceptions import MissingConfigSection, InvalidConfigSection, InvalidConfigFormat

logger = logging.getLogger(__name__)

class CatcherConfigParser(object):
    SERVER_SETTING_NAME = 'server'
    HANDLER_SETTING_NAME = 'handler'
    
    def __init__(self, defaults=None):
        self.default_string = defaults
        self.settings = self._set_defaults(defaults)
        self.valid = False
        
    def _set_defaults(self, d):
        '''
        Gets a list of defaults
        '''
        if isinstance(d, dict):
            return self._validate(d)
        elif d is None:
            return {}
        else:
            raise InvalidConfigFormat
        
    def _validate(self, settings):
        '''
        Validates that the settings have the correct sections
        '''
        logger.debug("Validating parsed json string")
        try:
            if not isinstance(settings[self.SERVER_SETTING_NAME], dict):
                raise InvalidConfigFormat
            if not isinstance(settings[self.HANDLER_SETTING_NAME], dict):
                raise InvalidConfigFormat
        except:
            raise MissingConfigSection
        return settings
    
    def read(self, string):
        logger.debug("Reading JSON string")
        try:
            print(repr(string))
            parsed = json.loads(string)
            self._validate(parsed)
            self.settings = parsed
        except ValueError as e:
            logger.error("Invalid settings format. {}. Using default settings.".format(e))
            self.settings = self._set_defaults(self.default_string)
        except InvalidConfigFormat:
            logger.error("Invalid settings format. Missing . Using default settings.".format(e))
            self.settings = self._set_defaults(self.default_string)
        else:
            self.valid = True
            
    def is_valid(self):
        return self.valid
    
    def get(section, option):
        if section.lower() is "server":
            settings = self.get_server_settings()
            try:
                return settings.get(option)
            except:
                raise InvalidConfigValue
        elif section.lower() is "handler":
            settings = self.get_handler_settings()
            try:
                return settings.get(option)
            except:
                raise InvalidConfigValue
        else:
            raise InvalidConfigSection
    
    def get_server_settings(self):
        '''
        Get the server settings
        '''
        return self.settings.get(self.SERVER_SETTING_NAME)
    
    def get_handler_settings(self):
        '''
        Get the handler settings
        '''
        return self.settings.get(self.HANDLER_SETTING_NAME)
        