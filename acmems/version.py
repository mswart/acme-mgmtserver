MAJOR = 0
MINOR = 1
PATCH = 0
STAGE = None

STRING = '.'.join([str(v) for v in [MAJOR, MINOR, PATCH, STAGE] if v is not None])
