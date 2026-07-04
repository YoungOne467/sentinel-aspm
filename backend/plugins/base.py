'''Base definitions for vulnerability scanner plugins.

This module defines the :class:`ScannerPlugin` abstract base class that all
backend scanner plugins must inherit from.  Concrete implementations provide a
human‑readable *name* and *description* and implement the asynchronous
:py:meth:`run` method which performs the scan and returns a
:class:`~backend.models.ScanResult` (imported elsewhere in the project).

The class is deliberately minimal – it only specifies the required public
attributes and method signature – so that individual plugins can focus on the
specific scanning logic while still being discoverable and type‑checked by the
rest of the application.
'''

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import ClassVar

# NOTE: ``ScanResult`` is defined in ``backend.models`` (or a similar module).
# It is imported lazily to avoid circular import problems – the concrete plugin
# implementation will have the actual import path available at runtime.

class ScannerPlugin(abc.ABC):
    """Abstract base class for all vulnerability scanner plugins.

    Attributes
    ----------
    name:
        A short, human‑readable identifier for the plugin.  Used by the UI and
        when logging which scanner performed a given scan.
    description:
        A longer description that explains what the plugin does, the type of
        vulnerabilities it looks for, and any special requirements.
    """

    #: The plugin name – subclasses must override this class variable.
    name: ClassVar[str]
    #: Human‑readable description – subclasses must override this class variable.
    description: ClassVar[str]

    @abc.abstractmethod
    async def run(self, target: str) -> "ScanResult":
        """Execute the scan against *target*.

        Parameters
        ----------
        target:
            The target to scan – typically a URL, IP address, filename, or any
            other identifier understood by the concrete scanner implementation.

        Returns
        -------
        ScanResult:
            A Pydantic ``BaseModel`` (defined elsewhere) containing the scan
            findings, metadata such as execution time, and any error messages.
        """

        raise NotImplementedError
