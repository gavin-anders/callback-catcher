class MissingConfigSection(Exception):
    pass

class InvalidConfigValue(Exception):
    pass

class InvalidConfigSection(Exception):
    pass

class InvalidConfigFormat(ValueError):
    pass

class FailedToStartServive(Exception):
    pass