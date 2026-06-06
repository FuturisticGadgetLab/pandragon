"""
Pandragon Operators Package

Operator session management, authentication, and presence.
"""

from .manager import OperatorManager, OperatorSession

__all__ = [
    'OperatorManager',
    'OperatorSession',
]
