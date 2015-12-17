from setuptools import setup  # Always prefer setuptools over distutils
from codecs import open  # To use a consistent encoding
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

from acmems import version

setup(
    name='acme-mgmtserver',
    version=version.STRING,

    description='Basic Python Server to execute ACME instead of dump clients',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/mswart/acme-mgmtserver',

    # Author details
    author='Malte Swart',
    author_email='mswart@devtation.de',

    # Choose your license
    license='GPL',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    # What does your project relate to?
    keywords='acme server client proxy letsencrypt',

    packages=['acmems'],

    install_requires=[
        'acme>=0.1.0',
        'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
        'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
        'PyOpenSSL>=0.15',  # X509Req.get_extensions (>=0.15)
        'IPy',
    ],

    scripts=['bin/acmems', 'bin/acme-register'],
)
