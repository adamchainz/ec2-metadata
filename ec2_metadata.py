# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import requests
from cached_property import cached_property

__author__ = 'Adam Johnson'
__email__ = 'me@adamj.eu'
__version__ = '1.1.0'

__all__ = ('ec2_metadata',)


SERVICE_URL = 'http://169.254.169.254/latest/'
DYNAMIC_URL = SERVICE_URL + 'dynamic/'
METADATA_URL = SERVICE_URL + 'meta-data/'
USERDATA_URL = SERVICE_URL + 'user-data/'


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
    def network(self):
        '''The network interface map is keyed by MAC address. This structure will
           be returned like how it is given in the metadata interface.'''
        return self.recursive_get_data(METADATA_URL, 'network/interfaces/macs/')

    # helper function, not really designed to be called directly by clients.
    # this works by recognizing that value-only keys don't have a trailing slash,
    # and keys with a trailing slash have subkeys.
    def recursive_get_data(self, baseurl, key):
        curr_url = baseurl + key
        if not key.endswith('/'):  # don't explore further, just fetch
            return requests.get(curr_url).text

        # trailing slash, need to explore further
        ret = {}
        for l in requests.get(curr_url).text.splitlines():
            lkey = l.rstrip('/')
            ret[lkey] = self.recursive_get_data(curr_url, l)

        return ret

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

    @cached_property
    def security_groups(self):
        return requests.get(METADATA_URL + 'security-groups').text.splitlines()

    @cached_property
    def user_data(self):
        resp = requests.get(USERDATA_URL)
        if resp.status_code == 404:
            return None
        else:
            return resp.content


ec2_metadata = EC2Metadata()
