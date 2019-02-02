.. :changelog:

History
-------

Pending Release
---------------

.. Insert new release notes below this line

2.0.0 (2019-02-02)
------------------

* Drop Python 2 support, only Python 3.4+ is supported now.

1.8.0 (2018-10-21)
------------------

* Use timeout of 1 second for requests to the metadata API.

1.7.1 (2018-09-17)
------------------

* Fix doucmentation rendering on PyPI.

1.7.0 (2018-09-17)
------------------

* Add ``interface_id`` to ``NetworkInterface``.

1.6.0 (2017-11-20)
------------------

* Add ``ipv6s``, ``subnet_ipv6_cidr_blocks``, and ``vpc_ipv6_cidr_blocks``
  attributes to ``NetworkInterface``.

1.5.0 (2017-10-29)
------------------

* Add ``instance_action`` and ``kernel_id`` attributes.

1.4.0 (2017-10-24)
------------------

* Add ``iam_info``, ``instance_profile_arn`` and ``instance_profile_id``
  attributes.
* Refactor handling non-200 responses to be more strict for attributes where
  404's are allowed.

1.3.1 (2017-10-17)
------------------

* Fix rendering of docs on PyPI.

1.3.0 (2017-10-17)
------------------

* All methods can now raise ``requests.exceptions.HTTPError`` if the metadata
  API returns a bad response, rather than failing during parsing or silently
  returning data from non-200 responses.
* ``EC2Metadata`` can now be passed a ``requests.Session`` object for
  customization of the way requests are made.

1.2.1 (2017-08-31)
------------------

* Make ``public_*`` properties return ``None`` for instances that aren't
  public.

1.2.0 (2017-08-26)
------------------

* Add ``network_interfaces`` attribute which is a list of ``NetworkInterface``
  instances, which have many attributes themselves.

1.1.0 (2017-08-07)
------------------

* Add ``security_groups`` and ``user_data`` attributes.

1.0.0 (2017-06-16)
------------------

* First release on PyPI, featuring ``ec2_metadata`` object.
