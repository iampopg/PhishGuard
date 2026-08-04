class PhishGuardError(Exception):
    pass


class ConfigurationError(PhishGuardError):
    pass


class MailboxConnectionError(PhishGuardError):
    pass


class AnalysisError(PhishGuardError):
    pass
