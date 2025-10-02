class DKDMConformityException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f'DKDM Conformity Exception : {self.msg}'


class KDMGenerationError(Exception):
    """Raised when KDM generation fails."""
    pass