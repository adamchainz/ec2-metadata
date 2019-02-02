import re

from setuptools import setup


def get_version(filename):
    with open(filename, 'r') as fp:
        contents = fp.read()
    return re.search(r"__version__ = ['\"]([^'\"]+)['\"]", contents).group(1)


version = get_version('ec2_metadata.py')


with open('README.rst', 'r') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst', 'r') as history_file:
    history = history_file.read().replace('.. :changelog:', '')


setup(
    name='ec2-metadata',
    version=version,
    description='An easy interface to query the EC2 metadata API, with caching.',
    long_description=readme + '\n\n' + history,
    author='Adam Johnson',
    author_email='me@adamj.eu',
    url='https://github.com/adamchainz/ec2-metadata',
    py_modules=['ec2_metadata'],
    include_package_data=True,
    install_requires=[
        'cached-property',
        'requests',
    ],
    python_requires='>=3.4',
    license='ISC License',
    zip_safe=False,
    keywords='AWS, EC2, metadata',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
