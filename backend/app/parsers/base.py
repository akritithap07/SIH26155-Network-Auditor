from abc import ABC, abstractmethod

from app.normalization.schema import NormalizedConfig


class BaseConfigParser(ABC):
    vendor: str = "unknown"
    config_format: str = "unknown"

    @abstractmethod
    def parse(self, config_text: str) -> NormalizedConfig:
        """
        Parse vendor-specific configuration into the universal schema.
        """
        raise NotImplementedError