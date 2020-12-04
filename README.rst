============
ec2-metadata
============

.. image:: https://img.shields.io/github/workflow/status/adamchainz/ec2-metadata/CI/master?style=for-the-badge
   :target: https://github.com/adamchainz/ec2-metadata/actions?workflow=CI

.. image:: https://img.shields.io/pypi/v/ec2-metadata.svg?style=for-the-badge
   :target: https://pypi.org/project/ec2-metadata/

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge
   :target: https://github.com/psf/black

.. image:: https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white&style=for-the-badge
   :target: https://github.com/pre-commit/pre-commit
   :alt: pre-commit

An easy interface to query the EC2 metadata API (version 2), with caching.

A quick example:

.. code-block:: python

    >>> from ec2_metadata import ec2_metadata
    >>> print(ec2_metadata.region)
    us-east-1
    >>> print(ec2_metadata.instance_id)
    i-123456


Installation
============

Use **pip**:

.. code-block:: sh

    python -m pip install ec2-metadata

Python 3.6 to 3.9 supported.

----

**Working on a Django project?**
Check out my book `Speed Up Your Django Tests <https://gumroad.com/l/suydt>`__ which covers loads of best practices so you can write faster, more accurate tests.

----

Why?
====

``boto`` came with a utility function to retrieve the instance metadata as a
lazy loading dictionary, ``boto.utils.get_instance_metadata``, but this has not
been ported to ``boto3``, as per `this issue
<https://github.com/boto/boto3/issues/313>`_. I thought that rather than
building a new version inside ``boto3`` it would work well as a standalone
library.

Instance Metadata Service Version 2
===================================

In November 2019, AWS released
`version 2 <https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/>`__
of the instance metadata service. It's more secure against Server Side Request
Forgery (SSRF) attacks.

``ec2-metadata`` now uses it exclusively. You can therefore consider disabling
version 1, as per
`AWS' guide <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-transition-to-version-2>`__.

API
===

``EC2Metadata(session=None)``
-----------------------------

A container that represents the data available on the EC2 metadata service.
Attributes don't entirely correspond to the paths in the metadata service -
they have been 'cleaned up'. You may also want to refer to the `metadata
service docs
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories>`_
to understand the exact contents.

There's a singleton instance of it at the name ``ec2_metadata`` which should
cover 90% of use cases. Use it like:

.. code-block:: python

    from ec2_metadata import ec2_metadata
    ec2_metadata.region

The ``session`` argument, if provided, should be an instance of
``requests.Session``, allowing you to customize the way requests are made.

Most of the attributes are cached, except where noted below. This is because
they are mostly immutable, or at least require an instance stop to change.
However some cached attributes do represent things that can change without an
instance stop, but rarely do, such as network devices.

The caching is done with ``@cached_property``, so they cache on first access.
If you want to clear the cache of one attribute you can just `del` it:

.. code-block:: python

    del ec2_metadata.network_interfaces

To clear all, use the ``clear_all()`` method as per below.


``account_id: str``
~~~~~~~~~~~~~~~~~~~

The current AWS account ID, e.g. ``'123456789012'``.

``ami_id: str``
~~~~~~~~~~~~~~~

The ID of the AMI used to launch the instance, e.g. ``'ami-123456'``.

``availability_zone: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The name of the current AZ e.g. ``'eu-west-1a'``.

``ami_launch_index: int``
~~~~~~~~~~~~~~~~~~~~~~~~~

The index of the instance in the launch request, zero-based, e.g. ``0``.

``ami_manifest_path: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The path to the AMI manifest file in Amazon S3, or ``'(unknown)'`` on
EBS-backed AMI's.

``clear_all() -> None``
~~~~~~~~~~~~~~~~~~~~~~~

Clear all the cached attributes on the class, meaning their next access will
re-fetch the data from the metadata API. This includes clearing the token used
to authenticate with the service.

``iam_info: dict``
~~~~~~~~~~~~~~~~~~

A dictionary of data for the IAM role attached to the instance, or ``None`` if
no role is attached.

``instance_action: str``
~~~~~~~~~~~~~~~~~~~~~~~~

**Uncached.** A state that notifies if the instance will reboot in preparation
for bundling. See the `AWS docs section “Instance Metadata Categories”
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories>`_
for the valid values.

``instance_id: str``
~~~~~~~~~~~~~~~~~~~~

The current instance's ID, e.g. ``'i-123456'``

``instance_identity_document: dict``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of dynamic data - see `AWS docs page “Instance Identity Documents”
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html>`_.

``instance_profile_arn: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ARN of the IAM role/instance profile attached to the instance, taken from
``iam_info``, or ``None`` if no role is attached.

``instance_profile_id: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ID of the IAM role/instance profile attached to the instance, taken from
``iam_info``, or ``None`` if no role is attached.

``instance_type: str``
~~~~~~~~~~~~~~~~~~~~~~

The current instance's type, e.g. ``'t2.nano'``

``kernel_id: str``
~~~~~~~~~~~~~~~~~~

The current instance's kernel ID, or ``None`` if it doesn't have one, e.g.
``'aki-dc9ed9af'``.

``mac : str``
~~~~~~~~~~~~~

The instance's MAC address, e.g. ``'0a:d2:ae:4d:f3:12'``

``network_interfaces: Dict[str, NetworkInterface]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of mac address to ``NetworkInterface``, which represents the data
available on a network interface - see below. E.g.
``{'01:23:45:67:89:ab': NetworkInterface('01:23:45:67:89:ab')}``

``private_hostname : str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The private IPv4 DNS hostname of the instance, e.g.
``'ip-172-30-0-0.eu-west-1.compute.internal'`` .

``private_ipv4: str``
~~~~~~~~~~~~~~~~~~~~~

The private IPv4 of the instance, e.g. ``'172.30.0.0'``.

``public_hostname : str``
~~~~~~~~~~~~~~~~~~~~~~~~~

The public DNS hostname of the instance, or ``None`` if the instance is not
public, e.g. ``'ec2-1-2-3-4.compute-1.amazonaws.com'``.

``public_ipv4: str``
~~~~~~~~~~~~~~~~~~~~

The public IPv4 address of the instance, or ``None`` if the instance is not
public, e.g. ``'1.2.3.4'``.

``region: str``
~~~~~~~~~~~~~~~

The region the instance is running in, e.g. ``'eu-west-1'``.

``reservation_id: str``
~~~~~~~~~~~~~~~~~~~~~~~

The ID of the reservation used to launch the instance, e.g.
``'r-12345678901234567'``.

``security_groups : List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

List of security groups by name, e.g. ``['ssh-access', 'custom-sg-1']``.

``user_data: bytes``
~~~~~~~~~~~~~~~~~~~~

The raw user data assigned to the instance (not base64 encoded), or ``None`` if
there is none.

``NetworkInterface``
--------------------

Represents a single network interface, as retrieved from
``EC2Metadata.network_interfaces``. Again like ``EC2Metadata`` all its
attributes cache on first access, and can be cleared with ``del`` or
its ``clear_all()`` method.

``device_number: int``
~~~~~~~~~~~~~~~~~~~~~~

The unique device number associated with that interface, e.g. ``0``.

``interface_id: str``
~~~~~~~~~~~~~~~~~~~~~

The unique id used to identify the Elastic Network Interface, e.g. ``'eni-12345'``.

``ipv4_associations: Dict[str, List[str]]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary mapping public IP addresses on the interface to the list of
private IP addresses associated with that public IP, for each public IP that is
associated with the interface, e.g. ``{'54.0.0.1': ['172.30.0.0']}``.

``ipv6s: List[str]``
~~~~~~~~~~~~~~~~~~~~

The IPv6 addresses associated with the interface, e.g.
``['2001:db8:abcd:ef00::1234']``.

``mac: str``
~~~~~~~~~~~~

The MAC address of the interface, e.g. ``'01:23:45:67:89:ab'``.

``owner_id: str``
~~~~~~~~~~~~~~~~~

The AWS Account ID of the owner of the network interface, e.g.
``'123456789012'``.

``private_hostname: str``
~~~~~~~~~~~~~~~~~~~~~~~~~

The interface's local/private hostname, e.g.
``'ip-172-30-0-0.eu-west-1.compute.internal'``.

``private_ipv4s: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The private IPv4 addresses associated with the interface, e.g.
``['172.30.0.0']``.

``public_hostname: str``
~~~~~~~~~~~~~~~~~~~~~~~~

The interface's public DNS (IPv4), e.g.
``'ec2-54-0-0-0.compute-1.amazonaws.com'``.

``public_ipv4s: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Elastic IP addresses associated with the interface, e.g. ``['54.0.0.0']``.

``security_groups: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The names of the security groups to which the network interface belongs, e.g.
``['ssh-access', 'custom-sg-1']``.

``security_group_ids: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The names of the security groups to which the network interface belongs, e.g.
``['sg-12345678', 'sg-12345679']``.

``subnet_id: str``
~~~~~~~~~~~~~~~~~~

The ID of the subnet in which the interface resides, e.g.
``'subnet-12345678'``.

``subnet_ipv4_cidr_block: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The IPv4 CIDR block of the subnet in which the interface resides, e.g.
``'172.30.0.0/24'``.

``subnet_ipv6_cidr_blocks: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv6 CIDR blocks of the subnet in which the interface resides, e.g.
``['2001:db8:abcd:ef00::/64']``. If the subnet does not have any IPv6 CIDR
blocks or the instance isn't in a VPC, the list will be empty, e.g. ``[]``.

``vpc_id: str``
~~~~~~~~~~~~~~~

The ID of the VPC in which the interface resides, e.g. ``'vpc-12345678'``.

``vpc_ipv4_cidr_block: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The IPv4 CIDR block of the VPC, or ``None`` if the instance isn't in a VPC,
e.g. ``'172.30.0.0/16'``.

``vpc_ipv4_cidr_blocks: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv4 CIDR blocks, or ``None`` if the instance isn't in a VPC, e.g.
``['172.30.0.0/16']``.

``vpc_ipv6_cidr_blocks: List[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv6 CIDR blocks of the VPC in which the interface resides, e.g.
``['2001:db8:abcd:ef00::/56']``. If the VPC does not have any IPv6 CIDR blocks
or the instance isn't in a VPC, the list will be empty, e.g. ``[]``.
