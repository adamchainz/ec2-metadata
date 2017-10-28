.. :changelog:

History
-------

Pending Release
---------------

.. Insert new release notes below this line

1.4.0 (2017-10-29)
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
