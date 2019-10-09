from setuptools import setup
import re
import ast


_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('bottle_jwt/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')
    ).group(1)))


setup(
    name='bottle-jwt',
    version=version,
    packages=['bottle_jwt'],
    url='',
    license='GLPv3',
    author='Papavassiliou Vassilis',
    author_email='vpapavasil@gmail.com',
    description='JWT Auth plugin for bottle.py applications',
    install_requires=['pyjwt']
)
