import os
import uuid

from pip.req import parse_requirements
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

install_reqs = parse_requirements(os.path.join(here, 'requirements.txt'), session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

with open(os.path.join(here, 'README.md')) as fp:
    long_description = fp.read()

setup(
    name='merkle-proofs',
    version='0.0.2',
    description='library for generating and validating Merkle Trees and receipts, compliant with chainpoint v2',
    author='MIT Media Lab Digital Certificates',
    tests_require=['tox'],
    url='https://github.com/digital-certificates/merkle-proofs',
    license='MIT',
    author_email='certs@media.mit.edu',
    long_description=long_description,
    packages=['merkleproof'],
    include_package_data=True,
    install_requires=reqs
)
