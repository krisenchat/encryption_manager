from setuptools import setup, find_packages

setup(
    name='encryption_manager',
    version='0.1.0',
    author='krisenchat',
    author_email='tiago.lacerda@krisenchat.de',
    description='A simple encryption manager package',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/krisenchat/encryption_manager',
    packages=find_packages(),
    install_requires=[
        'cryptography',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
