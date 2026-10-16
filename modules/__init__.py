"""Package des modules du bot patcheur APK.

Expose les sous-modules fonctionnels du bot. Aucun effet de bord lourd
n'est exécuté à l'importation : les dépendances coûteuses (par ex.
llama_cpp ou java) sont chargées uniquement lorsque le sous-module
correspondant est lui-même importé par l'appelant.
"""

from __future__ import annotations

import importlib
import logging
from typing import Final, List

__version__: Final[str] = "1.0.0"
__author__: Final[str] = "BOTS"
__license__: Final[str] = "MIT"

_SUBMODULES: Final[List[str]] = [
    "apk_analyzer",
    "patcher_core",
    "builder_64bit",
    "signer",
    "uploader",
    "telegram_sender",
]

__all__: Final[List[str]] = [
    "__version__",
    "__author__",
    "__license__",
    "SUPPORTED_ARCHITECTURES",
    "SUPPORTED_EXTENSIONS",
    "load_submodule",
    *_SUBMODULES,
]

SUPPORTED_ARCHITECTURES: Final[List[str]] = [
    "arm64-v8a",
    "armeabi-v7a",
    "x86_64",
]

SUPPORTED_EXTENSIONS: Final[List[str]] = [
    ".apk",
    ".apks",
    ".apkm",
    ".xapk",
    ".zip",
]

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())


def load_submodule(name: str) -> object:
    """Charge dynamiquement un sous-module du package.

    Parameters
    ----------
    name:
        Nom du sous-module sans le préfixe ``modules.``.

    Returns
    -------
    object
        Le module importé.

    Raises
    ------
    ValueError
        Si le nom n'est pas un sous-module déclaré.
    ImportError
        Si le sous-module existe mais que l'import échoue.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Le nom du sous-module doit être une chaîne non vide.")

    if name not in _SUBMODULES:
        raise ValueError(
            f"Sous-module inconnu : {name!r}. "
            f"Valeurs autorisées : {', '.join(_SUBMODULES)}."
        )

    try:
        return importlib.import_module(f"{__name__}.{name}")
    except ImportError:
        _logger.exception("Échec de l'importation du sous-module %s", name)
        raise


def __getattr__(attr_name: str) -> object:
    """Permet ``from modules import apk_analyzer`` sans import manuel.

    Le chargement reste paresseux : rien n'est importé tant que
    l'attribut n'est pas explicitement demandé.
    """
    if attr_name in _SUBMODULES:
        try:
            return importlib.import_module(f"{__name__}.{attr_name}")
        except ImportError:
            _logger.exception(
                "Échec de l'import paresseux du sous-module %s", attr_name
            )
            raise
    raise AttributeError(
        f"module {__name__!r} n'a pas d'attribut {attr_name!r}"
    )


def __dir__() -> List[str]:
    return sorted(set(list(globals().keys()) + _SUBMODULES))
