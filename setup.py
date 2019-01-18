from __future__ import print_function
import os
import functools
from setuptools import setup, Extension

base_modules = [
    Extension('_easyecc', [
        'pyeasyecc.cpp',
        ],
        libraries=['cryptopp'],
        extra_compile_args=['-fPIC'])
]


# if an extension is missing dependencies, distutils will attempt the build regardless
modules = [m for m in base_modules if functools.reduce(lambda x, y: x and os.path.exists(y), m.depends, True)]
missing_modules = [m for m in base_modules if m not in modules]
if missing_modules:
    print('WARNING: Some Python modules are missing dependencies: %s' % ', '.join(map(lambda x: x.name, missing_modules)))

setup(
    name='easyecc',
    description='''A simple wrapper around Crypto++ for Elliptical Curve Cryptography''',
    url='https://github.com/cureatr/easyecc',
    version='0.3',
    author='Alex Khomenko',
    author_email='khomenko@cs.stanford.edu',
    ext_modules=modules,
    py_modules=['easyecc'])
