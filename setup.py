import os
from setuptools import setup, find_packages

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def get_version():
    """
    Retrieve version from btlejuice.version module.
    """
    version = {}
    exec(read('btlejack/version.py'), version)
    return '.'.join([version['VERSION'], version['RELEASE']])

setup(
    name = "btlejack",
    python_requires='>3.5.2',
    version = get_version(),
    author = "Damien Cauquil",
    author_email = "damien.cauquil@digital.security",
    description = ("Bluetooth Low Energy Swiss-army knife to sniff, jam and hijack connections"),
    long_description = read('README.rst'),
    url = 'https://github.com/virtualabs/btlejack',
    license = "MIT",
    keywords = "bluetooth smart low energy hijack sniff jam",
    packages=find_packages(),
    install_requires=[
            'pyserial',
            'argparse',
            'halo'
    ],
    entry_points= {
        'console_scripts': [
            'btlejack=btlejack:main',
        ]
    },
    package_data = {'btlejack' : ['data/btlejack-fw-v1.hex', 'data/btlejack-fw-v2.hex', 'LICENSE']}
)
