from distutils.core import setup
from bottle_jwt import __version__ as version


setup(
    name='bottle-jwt',
    version=version,
    packages=['bottle_jwt'],
    url='',
    license='GLPv3',
    author='Papavassiliou Vassilis',
    author_email='vpapavasil@gmail.com',
    description='JWT Auth plugin for bottle.py applications'
)
