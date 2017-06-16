============
ec2-metadata
============

.. image:: https://img.shields.io/travis/adamchainz/ec2-metadata/master.svg
        :target: https://travis-ci.org/adamchainz/ec2-metadata

.. image:: https://img.shields.io/pypi/v/ec2-metadata.svg
        :target: https://pypi.python.org/pypi/ec2-metadata

An easy interface to query the EC2 metadata API, with caching.

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

    pip install ec2-metadata

Tested on Python 2.7 and Python 3.6.

Why?
====

``boto`` came with a utility function to retrieve the instance metadata as a
lazy loading dictionary, ``boto.utils.get_instance_metadata``, but this has not
been ported to ``boto3``, as per `this issue
<https://github.com/boto/boto3/issues/313>`_. I thought that rather than
building a new version inside ``boto3`` it would work well as a standalone
library.

Usage
=====

There is a special singleton object in the module to import:

.. code-block:: python

    from ec2_metadata import ec2_metadata

This object has a number of lazy attributes that pull the respective data from
the metadata service on first access, which are documented below. Attributes
don't entirely correspond to the paths in the metadata service - they have been
'cleaned up'. You may also want to refer to the `metadata service docs
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories>`_
to understand what's there.

============================== ========
Attribute Name                 Contents
============================== ========
``account_id``                 The current AWS account ID, e.g. ``'123456789012'``
``ami_id``                     The ID of the AMI used to launch the instance, e.g. ``'ami-123456'``
``availability_zone``          The name of the current AZ e.g. ``'eu-west-1a'``
``ami_launch_index``           The index of the instance in the launch request, zero-based, e.g. ``0``
``ami_manifest_path``          The path to the AMI manifest file in Amazon S3, or ``'(unknown)'`` on EBS-backed AMI's
``instance_id``                The current instance's ID, e.g. ``'i-123456'``
``instance_identity_document`` A dictionary of dynamic data, see `AWS docs <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html>`_
``instance_type``              The current instance's type, e.g. ``'t2.nano'``
``mac``                        The instance's MAC address, e.g. ``'0a:d2:ae:4d:f3:12'``
``private_hostname``           The private IPv4 DNS hostname of the instance, e.g. ``'ip-172-30-0-0.eu-west-1.compute.internal'``
``private_ipv4``               The private IPv4 of the instance, e.g. ``'172.30.0.0'``
``public_hostname``            The public DNS hostname of the instance, e.g. ``'ec2-1-2-3-4.compute-1.amazonaws.com'``
``public_ipv4``                The public IPv4 address of the instance, e.g. ``'1.2.3.4'``
``region``                     The region the instance is running in, e.g. ``'eu-west-1'``
``reservation_id``             The ID of the reservation used to launch the instance, e.g. ``'r-12345678901234567'``
============================== ========

These values should all be safe to cache for the lifetime of your Python
process, since they are (nearly entirely) immutable (some things can change,
e.g. ``public_ipv4`` when you attach an Elastic IP to the instance). If you
need to flush the caching, you can call ``ec2_metadata.clear_all()`` to wipe it
all.
