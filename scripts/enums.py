from enum import Enum


class FA(Enum):
    UNSAFE = 0
    CONSTRAINED = 1
    SELF = 2
    NONE = 3


class XSS(Enum):
    UNSAFE = 0
    SAFE = 1


class TLS(Enum):
    UNSAFE = 0
    ENABLED = 1


class XFO(Enum):
    UNSAFE = 0
    SELF = 1
    NONE = 2


class HSTSAge(Enum):
    DISABLE = -1
    UNSAFE = 0
    LOW = 1
    BIG = 2


class HSTSSub(Enum):
    UNSAFE = 0
    SAFE = 1


class CookieSecure(Enum):
    UNSAFE = 0
    SAFE = 1


class CookieHttpOnly(Enum):
    UNSAFE = 0
    SAFE = 1


class CookieSameSite(Enum):
    NONE = 0
    LAX = 1
    STRICT = 2
