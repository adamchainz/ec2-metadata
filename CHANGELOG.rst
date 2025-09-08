=========
Changelog
=========

2.16.0 (2025-09-09)
-------------------

* Support Python 3.14.

2.15.0 (2025-08-01)
-------------------

* Add ``public_keys`` attribute and ``PublicKey`` class.

  Thanks to Adam Novak in `PR #562 <https://github.com/adamchainz/ec2-metadata/pull/562>`__.

2.14.0 (2024-10-27)
-------------------

* Add ``instance_life_cycle`` attribute.

  Thanks to Zeev Rotshtein for the feature request in `Issue #440 <https://github.com/adamchainz/ec2-metadata/issues/440>`__.

* Drop Python 3.8 support.

* Support Python 3.13.

2.13.0 (2023-07-10)
-------------------

* Drop Python 3.7 support.

2.12.0 (2023-06-13)
-------------------

* Support Python 3.12.

2.11.0 (2022-12-06)
-------------------

* Improve type hints for the ``iam_info``, ``iam_security_credentials``, and ``instance_identity_document`` attributes, with ``TypedDict``\s on Python 3.8+.

2.10.0 (2022-05-11)
-------------------

* Support Python 3.11.

2.9.1 (2022-03-29)
------------------

* Return ``None`` for ``availability_zone_id`` when the underlying endpoint returns HTTP 404.

  Thanks to Amir Rossert in `PR #350 <https://github.com/adamchainz/ec2-metadata/pull/350>`__.

2.9.0 (2022-03-25)
------------------

* Add ``autoscaling_target_lifecycle_state`` attribute, as per `AWS announcement <https://aws.amazon.com/about-aws/whats-new/2022/03/amazon-ec2-auto-scaling-lifecycle-instance-metadata/>`__.

2.8.0 (2022-03-08)
------------------

* Add ``tags`` attribute, a mapping of the instance tags.
  This requires the corresponding EC2 feature to be enabled on the instance.

  Thanks to Renan Rodrigues in `PR #344 <https://github.com/adamchainz/ec2-metadata/pull/344>`__.

* Add ``spot_instance_action`` attribute.

  Thanks to Quimey Vivas in `PR #346 <https://github.com/adamchainz/ec2-metadata/pull/346>`__.

* Add ``domain`` and ``partition`` attributes.

  Thanks to Terry Griffin in `PR #339 <https://github.com/adamchainz/ec2-metadata/pull/339>`__.

* Add ``instance_profile_name`` and ``iam_security_credentials`` attributes.

  Thanks to Jean-Sebastien Jeannotte in `PR #313 <https://github.com/adamchainz/ec2-metadata/pull/313>`__.

2.7.0 (2022-01-10)
------------------

* Drop Python 3.6 support.

2.6.0 (2021-12-04)
------------------

* Support Python 3.10.

2.5.0 (2021-08-05)
------------------

* Add ``availability_zone_id`` attribute.
* Add type hints.

2.4.0 (2021-05-13)
------------------

* Use ``functools.cached_property`` on Python 3.8+, removing the dependency on
  the ``cached-property`` package.

* Stop distributing tests to reduce package size. Tests are not intended to be
  run outside of the tox setup in the repository. Repackagers can use GitHub's
  tarballs per tag.

2.3.0 (2020-12-13)
------------------

* Drop Python 3.5 support.
* Support Python 3.9.
* Move license from ISC to MIT License.

2.2.0 (2020-03-12)
------------------

* Move to use Instance Metadata Service version 2. See the README for a note on
  its increased security and porting to lock down the less secure version 1.
  Thanks ThrawnCA and antuarc for the initial PR.
  (`Issue #150 <https://github.com/adamchainz/ec2-metadata/issues/150>`__)

2.1.0 (2019-12-19)
------------------

* Update Python support to 3.5-3.8, as 3.4 has reached its end of life.
* Converted setuptools metadata to configuration file. This meant removing the
  ``__version__`` attribute from the package. If you want to inspect the
  installed version, use
  ``importlib.metadata.version("ec2-metadata")``
  (`docs <https://docs.python.org/3.8/library/importlib.metadata.html#distribution-versions>`__ /
  `backport <https://pypi.org/project/importlib-metadata/>`__).

2.0.0 (2019-02-02)
------------------

* Drop Python 2 support, only Python 3.4+ is supported now.

1.8.0 (2018-10-21)
------------------

* Use timeout of 1 second for requests to the metadata API.

1.7.1 (2018-09-17)
------------------

* Fix documentation rendering on PyPI.

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
