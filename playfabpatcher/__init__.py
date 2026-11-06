"""Universal Unity PlayFab patcher.

Repoints a game's PlayFab title id, developer secret key and environment URL
inside Unity games (Mono and IL2CPP) so a private or self hosted PlayFab style
backend can be used instead of the one the game shipped with.

Public entry points live in :mod:`playfabpatcher.scan` (detection),
:mod:`playfabpatcher.patch` (apply / verify / restore) and
:mod:`playfabpatcher.gui` (desktop UI).
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
