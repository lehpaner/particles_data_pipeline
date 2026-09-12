from .auth import *  # noqa: F401,F403
from . import auth as _auth

# re-export everything auth.py defines at module level, so `import auth`
# (used by main.py) behaves the same as importing auth/auth.py directly.
globals().update({k: v for k, v in vars(_auth).items() if not k.startswith("_")})
