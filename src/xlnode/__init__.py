# xlnode/__init__.py

""" Node library for python XLattice packages. """

__version__ = '0.0.6'
__version_date__ = '2017-08-05'

__all__ = ['__version__', '__version_date__', 'XLNodeError', ]


class XLNodeError(RuntimeError):
    """ General purpose exception for the package. """
