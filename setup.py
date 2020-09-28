from setuptools import setup, Extension

modules = [
    Extension('_easyecc', [
        'pyeasyecc.cpp',
        ],
        include_dirs=["/opt/local/include"],
        library_dirs=["/opt/local/lib"],
        # On macos "port install libcryptopp", or "brew install cryptopp"
        # On Ubuntu "apt install libcrypto++6 libcrypto++-dev"
        libraries=['cryptopp'],
        extra_compile_args=['-fPIC'])
]

setup(
    name='easyecc',
    description='''A simple wrapper around Crypto++ for Elliptical Curve Cryptography''',
    url='https://github.com/cureatr/easyecc',
    version='0.5',
    author='Alex Khomenko',
    author_email='khomenko@cs.stanford.edu',
    ext_modules=modules,
    py_modules=['easyecc'])
