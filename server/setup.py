from setuptools import setup, Extension
from Cython.Build import cythonize

ext = Extension(
    "protocol.parser",
    sources=["protocol/parser.pyx"],
)

setup(
    ext_modules=cythonize(ext)
)
