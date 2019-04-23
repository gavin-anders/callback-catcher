import json
import logging
import copy

from .catcherexceptions import MissingConfigSection, InvalidConfigSection, InvalidConfigFormat

logger = logging.getLogger(__name__)

class CatcherConfigParser(object):    
    def __init__(self, defaults=None):
        self.default_string = defaults
        self.settings = self._set_defaults(defaults)
        self.gubbins = self._set_defaults(defaults)
        self.valid = False
        
    def _set_defaults(self, d):
        '''
        Gets a list of defaults
        '''
        if isinstance(d, dict):
            d = self._validate(d)
            return copy.deepcopy(d)
        elif d is None:
            return {}
        else:
            raise InvalidConfigFormat
        
    def _validate(self, settings):
        '''
        Validates that the settings have the correct sections
        '''
        try:
            if not isinstance(settings, dict):
                raise InvalidConfigFormat
        except:
            raise MissingConfigSection
        return settings
    
    def read(self, string):
        try:
            parsed = json.loads(string)
            self._validate(parsed)
            self.settings = parsed
        except ValueError as e:
            logger.error("Invalid settings format. {}. Using default settings.".format(e))
            self.settings = self._set_defaults(self.default_string)
        except InvalidConfigFormat:
            logger.error("Invalid settings format. Should be a dict. Using default settings.")
            self.settings = self._set_defaults(self.default_string)
        else:
            self.valid = True
            
    def is_valid(self):
        return self.valid
    
    def get_config(self, json_format=False):
        '''
        Alias function
        '''
        if json_format is True:
            return json.dumps(self.settings)
        return self.settings
    
    def add_config(self, name, value):
        '''
        Add new setting if doesnt already exist
        '''
        self.settings[name] = value
        