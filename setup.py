import os
from setuptools import setup, find_packages
from btlejack.version import VERSION

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "btlejack",
    version = VERSION,
    author = "Damien Cauquil",
    author_email = "damien.cauquil@digital.security",
    description = ("Bluetooth Low Energy Swiss-army knife to sniff, jam and hijack connections"),
    long_description = read('README.rst'),
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
    package_data = {'btlejack' : ['data/btlejack-fw.hex', 'LICENSE']}
)
