from setuptools import setup, find_packages

setup(
    name='django-secretkey',
    version='0.1-dev',
    test_suite='secretkey.tests',
    packages=find_packages(),
    install_requires=['lockfile'],
    package_data={'secretkey': []},
    include_package_data=True,
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    long_description=open('README.rst').read(),
)
