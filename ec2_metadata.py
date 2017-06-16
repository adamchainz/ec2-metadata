# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import requests
from cached_property import cached_property

__author__ = 'Adam Johnson'
__email__ = 'me@adamj.eu'
__version__ = '1.0.0'

__all__ = ('ec2_metadata',)


SERVICE_URL = 'http://169.254.169.254/2016-09-02/'
DYNAMIC_URL = SERVICE_URL + 'dynamic/'
METADATA_URL = SERVICE_URL + 'meta-data/'


class EC2Metadata(object):

    def clear_all(self):
        for key in tuple(self.__dict__.keys()):
            if isinstance(getattr(self.__class__, key), cached_property):
                del self.__dict__[key]

    @property
    def account_id(self):
        return self.instance_identity_document['accountId']

    @cached_property
    def ami_id(self):
        return requests.get(METADATA_URL + 'ami-id').text

    @cached_property
    def availability_zone(self):
        return requests.get(METADATA_URL + 'placement/availability-zone').text

    @cached_property
    def ami_launch_index(self):
        return int(requests.get(METADATA_URL + 'ami-launch-index').text)

    @cached_property
    def ami_manifest_path(self):
        return requests.get(METADATA_URL + 'ami-manifest-path').text

    @cached_property
    def instance_id(self):
        return requests.get(METADATA_URL + 'instance-id').text

    @cached_property
    def instance_identity_document(self):
        return requests.get(DYNAMIC_URL + 'instance-identity/document').json()

    @cached_property
    def instance_type(self):
        return requests.get(METADATA_URL + 'instance-type').text

    @cached_property
    def mac(self):
        return requests.get(METADATA_URL + 'mac').text

    @cached_property
    def private_hostname(self):
        return requests.get(METADATA_URL + 'local-hostname').text

    @cached_property
    def private_ipv4(self):
        return requests.get(METADATA_URL + 'local-ipv4').text

    @cached_property
    def public_hostname(self):
        return requests.get(METADATA_URL + 'public-hostname').text

    @cached_property
    def public_ipv4(self):
        return requests.get(METADATA_URL + 'public-ipv4').text

    @cached_property
    def region(self):
        return self.instance_identity_document['region']

    @cached_property
    def reservation_id(self):
        return requests.get(METADATA_URL + 'reservation-id').text


ec2_metadata = EC2Metadata()
