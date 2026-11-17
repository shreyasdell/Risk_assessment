"""
Base Section Class

All report sections inherit from this class.
"""

from abc import ABC, abstractmethod
from typing import List
from reportlab.platypus import Flowable


class BaseSection(ABC):
    """Base class for all report sections."""
    
    def __init__(self, styles, colors):
        self.styles = styles
        self.colors = colors
    
    @abstractmethod
    def generate(self, data: dict) -> List[Flowable]:
        """Generate the section content.
        
        Args:
            data: Dictionary containing report data
            
        Returns:
            List of Flowable objects for the section
        """
        pass
