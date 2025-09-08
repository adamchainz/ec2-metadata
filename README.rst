============
ec2-metadata
============

.. image:: https://img.shields.io/github/actions/workflow/status/adamchainz/ec2-metadata/main.yml.svg?branch=main&style=for-the-badge
   :target: https://github.com/adamchainz/ec2-metadata/actions?workflow=CI

.. image:: https://img.shields.io/badge/Coverage-100%25-success?style=for-the-badge
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

.. code-block:: pycon

    >>> from ec2_metadata import ec2_metadata
    >>> print(ec2_metadata.region)
    us-east-1
    >>> print(ec2_metadata.instance_id)
    i-123456

----

**Working on a Django project?**
Improve your skills with `one of my books <https://adamj.eu/books/>`__.

----

Installation
============

Use **pip**:

.. code-block:: sh

    python -m pip install ec2-metadata

Python 3.9 to 3.14 supported.

Why?
====

``boto`` came with a utility function to retrieve the instance metadata as a lazy loading dictionary, ``boto.utils.get_instance_metadata``, but this has not been ported to ``boto3``, as per `this issue <https://github.com/boto/boto3/issues/313>`_.
I thought that rather than building a new version inside ``boto3`` it would work well as a standalone library.

Instance Metadata Service Version 2
===================================

In November 2019, AWS released `version 2 <https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/>`__ of the instance metadata service.
It's more secure against Server Side Request Forgery (SSRF) attacks.

``ec2-metadata`` now uses it exclusively.
So, you may consider disabling version 1, as per `AWS' guide <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-transition-to-version-2>`__.

**Note:** Instance Metadata Service v2 has a default IP hop limit of 1.
This can mean that you can see ``requests.exceptions.ReadTimeout`` errors from within Docker containers.
To solve this, reconfigure your EC2 instance’s metadata options to allow three hops with |aws ec2 modify-instance-metadata-options|__:

.. |aws ec2 modify-instance-metadata-options| replace:: ``aws ec2 modify-instance-metadata-options``
__ https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-metadata-options.html

.. code-block:: bash

    aws ec2 modify-instance-metadata-options  --instance-id <instance-id> --http-put-response-hop-limit 3

API
===

``EC2Metadata(session=None)``
-----------------------------

A container that represents the data available on the EC2 metadata service.
Attributes don't entirely correspond to the paths in the metadata service—they have been 'cleaned up'.
You may also want to refer to the `metadata service docs <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_ to understand the exact contents.

There's a singleton instance of it at the name ``ec2_metadata`` which should cover most use cases.
Use it like:

.. code-block:: python

    from ec2_metadata import ec2_metadata

    ec2_metadata.region

The ``session`` argument, if provided, should be an instance of |requests.Session|__, allowing you to customize the way requests are made.

.. |requests.Session| replace:: ``requests.Session``
__ https://docs.python-requests.org/en/latest/user/advanced/

Most of the attributes are cached, except where noted below.
This is because they are mostly immutable, or at least require an instance stop to change.
However some cached attributes do represent things that can change without an instance stop, but rarely do, such as network devices.

The caching is done with |@cached_property|__, so they cache on first access.
If you want to clear the cache of one attribute you can just `del` it:

.. |@cached_property| replace:: ``@cached_property``
__ https://docs.python.org/3/library/functools.html#functools.cached_property

.. code-block:: python

    del ec2_metadata.network_interfaces

To clear all, use the ``clear_all()`` method as per below.

``account_id: str``
~~~~~~~~~~~~~~~~~~~

The current AWS account ID, for example ``'123456789012'``.

``ami_id: str``
~~~~~~~~~~~~~~~

The ID of the AMI used to launch the instance, for example ``'ami-123456'``.

``autoscaling_target_lifecycle_state: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Uncached.**

The target Auto Scaling lifecycle state that the instance is transitionioning to, or ``None`` if the instance is not in an autoscaling group.
See AWS docs page `Retrieve the target lifecycle state through instance metadata <https://docs.aws.amazon.com/autoscaling/ec2/userguide/retrieving-target-lifecycle-state-through-imds.html>`__.

``availability_zone: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The name of the current AZ, for example ``'eu-west-1a'``.

``availability_zone_id: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The unique, cross-account ID of the current AZ, for example ``'use1-az6'``.
See AWS docs page `AZ IDs for your AWS resources <https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html>`__.

``ami_launch_index: int``
~~~~~~~~~~~~~~~~~~~~~~~~~

The index of the instance in the launch request, zero-based, for example ``0``.

``ami_manifest_path: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The path to the AMI manifest file in Amazon S3, or ``'(unknown)'`` on EBS-backed AMI's.

``clear_all() -> None``
~~~~~~~~~~~~~~~~~~~~~~~

Clear all the cached attributes on the class, meaning their next access will re-fetch the data from the metadata API.
This includes clearing the token used to authenticate with the service.

``domain: str``
~~~~~~~~~~~~~~~

The domain for AWS resources for the region.
For example: ``'amazonaws.com'`` for the standard AWS regions and GovCloud (US), or ``'amazonaws.com.cn'`` for China.

``iam_info: IamInfoDict | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of data for the IAM role attached to the instance, or ``None`` if no role is attached.
The dict has this type, based on what the metadata service returns:

.. code-block:: python

    class IamInfoDict(TypedDict):
        InstanceProfileArn: str
        InstanceProfileId: str
        LastUpdated: str

``iam_security_credentials: IamSecurityCredentialsDict | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of data for the security credentials associated with the IAM role attached to the instance, or ``None`` if no role is attached.
See the `AWS docs section “Retrieve security credentials from instance metadata” <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials>`__ for details.
The dict has this type, based on that document:

.. code-block:: python

    class IamSecurityCredentialsDict(TypedDict):
        LastUpdated: str
        Type: str
        AccessKeyId: str
        SecretAccessKey: str
        Token: str
        Expiration: str

``instance_action: str``
~~~~~~~~~~~~~~~~~~~~~~~~

**Uncached.**

A state that notifies if the instance will reboot in preparation for bundling.
See the `AWS docs section “Instance Metadata Categories” <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html>`_ for the valid values.

``instance_id: str``
~~~~~~~~~~~~~~~~~~~~

The current instance's ID, for example ``'i-123456'``.

``instance_identity_document: InstanceIdentityDocumentDict``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of dynamic data about the instance.
See the `AWS docs page “Instance Identity Documents” <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html>`__ for an explanation of the contents.
The dict has this type, based on that document:

.. code-block:: python

    class InstanceIdentityDocumentDict(TypedDict):
        accountId: str
        architecture: Literal["i386", "x86_64", "arm64"]
        availabilityZone: str
        billingProducts: list[str] | None
        marketplaceProductCodes: list[str] | None
        imageId: str
        instanceId: str
        instanceType: str
        kernelId: str | None
        pendingTime: str
        privateIp: str
        ramdiskId: str | None
        region: str
        version: str

``instance_life_cycle: str``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The purchasing option of this instance, for example ``'on-demand'``.

``instance_profile_arn: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ARN of the IAM role/instance profile attached to the instance, taken from ``iam_info``, or ``None`` if no role is attached.

``instance_profile_id: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ID of the IAM role/instance profile attached to the instance, taken from ``iam_info``, or ``None`` if no role is attached.


``instance_profile_name: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The instance profile name, extracted from ``instance_profile_arn``, or ``None`` if no role is attached.

``instance_type: str``
~~~~~~~~~~~~~~~~~~~~~~

The current instance's type, for example ``'t2.nano'``.

``kernel_id: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~

The current instance's kernel ID, or ``None`` if it doesn't have one, for example ``'aki-dc9ed9af'``.

``mac : str``
~~~~~~~~~~~~~

The instance's MAC address, for example ``'0a:d2:ae:4d:f3:12'``.

``network_interfaces: dict[str, NetworkInterface]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of mac address to ``NetworkInterface``, which represents the data available on a network interface, documented below.
For example: ``{'01:23:45:67:89:ab': NetworkInterface('01:23:45:67:89:ab')}``

``partition: str``
~~~~~~~~~~~~~~~~~~

The AWS partition where the instance is running.
For example: ``'aws'`` for the standard AWS regions, ``'aws-us-gov'`` for GovCloud (US), or ``'aws-cn'`` for China.

``private_hostname : str``
~~~~~~~~~~~~~~~~~~~~~~~~~~

The private IPv4 DNS hostname of the instance, for example ``'ip-172-30-0-0.eu-west-1.compute.internal'`` .

``private_ipv4: str``
~~~~~~~~~~~~~~~~~~~~~

The private IPv4 of the instance, for example ``'172.30.0.0'``.

``public_hostname : str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The public DNS hostname of the instance, or ``None`` if the instance is not public.
For example: ``'ec2-1-2-3-4.compute-1.amazonaws.com'``.

``public_ipv4: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The public IPv4 address of the instance, or ``None`` if the instance is not public.
For example: ``'1.2.3.4'``.

``public_keys: dict[str, PublicKey]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary of key name to ``PublicKey``, which represents data available on an SSH public key, documented below.
These keys represent the SSH keys authorized to log into the instance when it was created.
For example: ``{'somekey': PublicKey(0)}``
If no public keys are available, this will be an empty dictionary.

``region: str``
~~~~~~~~~~~~~~~

The region the instance is running in, for example ``'eu-west-1'``.

``reservation_id: str``
~~~~~~~~~~~~~~~~~~~~~~~

The ID of the reservation used to launch the instance, for example ``'r-12345678901234567'``.

``security_groups : list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

List of security groups by name, for example ``['ssh-access', 'custom-sg-1']``.

``spot_instance_action: SpotInstanceAction | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Uncached.**

An object describing an action about to happen to this spot instance.
Returns ``None`` if the instance is not spot, or not marked for termination.

The ``SpotInstanceAction`` object has two attributes:

* ``action: str`` - the action about to happen, one of ``"hibernate"``, ``"stop"``, or ``"terminate"``.
* ``time: datetime`` - the approximate UTC datetime when the action will occur.

See `AWS docs section <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-instance-termination-notices.html#instance-action-metadata>`__ for a little more information.

``tags: InstanceTags``
~~~~~~~~~~~~~~~~~~~~~~

A dict-like mapping of the tags for the instance (documented below).
This requires you to `explicitly enable the feature <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#allow-access-to-tags-in-IMDS>`__ for the instance.
If the feature is not enabled, accessing this attribute raises an error.

(It also seems that there is a bug where if the feature is enabled and then disabled, the metadata service returns an empty response.
This is indistinguishable from “no tags”, so beware that in that case, ``InstanceTags`` will just look like an empty mapping.)

``user_data: bytes | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The raw user data assigned to the instance (not base64 encoded), or ``None`` if there is none.

``InstanceTags``
----------------

A dict-like mapping of tag names to values (both ``str``\s).
To avoid unnecessary requests, the mapping is lazy: values are only fetched when required.
(Names are known on construction though, from the first request in ``EC2Metadata.tags``.)

The metadata service will receive tag updates on some instance types, as per `the AWS documentation <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#work-with-tags-in-IMDS>`__:

    If you add or remove an instance tag, the instance metadata is updated while the instance is running for instances built on the Nitro System, without needing to stop and then start the instance.
    For all other instances, to update the tags in the instance metadata, you must stop and then start the instance.

Because ``InstanceTags`` is cached, it won’t reflect such updates on Nitro instances unless you clear it first:

.. code-block:: python

    del ec2_metadata.tags
    ec2_metadata.tags["Name"]  # fresh

``NetworkInterface``
--------------------

Represents a single network interface, as retrieved from ``EC2Metadata.network_interfaces``.
Again like ``EC2Metadata`` all its attributes cache on first access, and can be cleared with ``del`` or its ``clear_all()`` method.

``device_number: int``
~~~~~~~~~~~~~~~~~~~~~~

The unique device number associated with that interface, for example ``0``.

``interface_id: str``
~~~~~~~~~~~~~~~~~~~~~

The unique id used to identify the Elastic Network Interface, for example ``'eni-12345'``.

``ipv4_associations: dict[str, list[str]]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dictionary mapping the interface’s public IP addresses on the interface to the list of private IP addresses associated with that public IP.
For example: ``{'54.0.0.1': ['172.30.0.0']}``.

``ipv6s: list[str]``
~~~~~~~~~~~~~~~~~~~~

The IPv6 addresses associated with the interface, for example ``['2001:db8:abcd:ef00::1234']``.

``mac: str``
~~~~~~~~~~~~

The MAC address of the interface, for example ``'01:23:45:67:89:ab'``.

``owner_id: str``
~~~~~~~~~~~~~~~~~

The AWS Account ID of the owner of the network interface, for example ``'123456789012'``.

``private_hostname: str``
~~~~~~~~~~~~~~~~~~~~~~~~~

The interface's local/private hostname, for example ``'ip-172-30-0-0.eu-west-1.compute.internal'``.

``private_ipv4s: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The private IPv4 addresses associated with the interface, for example ``['172.30.0.0']``.

``public_hostname: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The interface's public DNS (IPv4), for example ``'ec2-54-0-0-0.compute-1.amazonaws.com'``.

``public_ipv4s: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Elastic IP addresses associated with the interface, for example ``['54.0.0.0']``.

``security_groups: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The names of the security groups to which the network interface belongs, for example ``['ssh-access', 'custom-sg-1']``.

``security_group_ids: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The names of the security groups to which the network interface belongs, for example ``['sg-12345678', 'sg-12345679']``.

``subnet_id: str``
~~~~~~~~~~~~~~~~~~

The ID of the subnet in which the interface resides, for example ``'subnet-12345678'``.

``subnet_ipv4_cidr_block: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The IPv4 CIDR block of the subnet in which the interface resides, or ``None`` if there is none, for example ``'172.30.0.0/24'``.

``subnet_ipv6_cidr_blocks: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv6 CIDR blocks of the subnet in which the interface resides, for example ``['2001:db8:abcd:ef00::/64']``.
If the subnet does not have any IPv6 CIDR blocks or the instance isn't in a VPC, the list will be empty, for example ``[]``.

``vpc_id: str``
~~~~~~~~~~~~~~~

The ID of the VPC in which the interface resides, for example ``'vpc-12345678'``.

``vpc_ipv4_cidr_block: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The IPv4 CIDR block of the VPC, or ``None`` if the instance isn't in a VPC, for example ``'172.30.0.0/16'``.

``vpc_ipv4_cidr_blocks: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv4 CIDR blocks for example ``['172.30.0.0/16']``.
If the interface doesn’t have any such CIDR blocks, the list will be empty.

``vpc_ipv6_cidr_blocks: list[str]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The list of IPv6 CIDR blocks of the VPC in which the interface resides, for example ``['2001:db8:abcd:ef00::/56']``.
If the VPC does not have any IPv6 CIDR blocks or the instance isn't in a VPC, the list will be empty, for example ``[]``.

``PublicKey``
-------------

Represents a single SSH public key, as retrieved from ``EC2Metadata.public_keys``.
Again like ``EC2Metadata`` all its attributes cache on first access, and can be cleared with ``del`` or its ``clear_all()`` method.

``openssh_key: str | None``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SSH public key in OpenSSH format, with a trailing newline, for example: ``ssh-rsa AAAAblahblahblah= exampleuser@examplehost\n``.
If the key is not available in OpenSSH format, this will be ``None``, however that is unlikely as that is the only format currently supported by the metadata service.
