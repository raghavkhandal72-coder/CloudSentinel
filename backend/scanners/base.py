from abc import ABC, abstractmethod
from typing import Any


class BaseScanner(ABC):
    """
    Base class for all cloud scanners.
    """
    def __init__(self):
        self.is_authenticated = False

    @abstractmethod
    def scan_all(self) -> list[dict[str, Any]]:
        """
        Executes all configured checks and returns a list of findings.
        """
