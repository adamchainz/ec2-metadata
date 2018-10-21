# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import requests
from cached_property import cached_property

__author__ = 'Adam Johnson'
__email__ = 'me@adamj.eu'
__version__ = '1.8.0'

__all__ = ('ec2_metadata',)


# We purposefully use a fixed version of the service rather than 'latest' in
# case any backward incompatible changes are made in the future
SERVICE_URL = 'http://169.254.169.254/2016-09-02/'
DYNAMIC_URL = SERVICE_URL + 'dynamic/'
METADATA_URL = SERVICE_URL + 'meta-data/'
USERDATA_URL = SERVICE_URL + 'user-data/'


class BaseLazyObject(object):

    def clear_all(self):
        for key in tuple(self.__dict__.keys()):
            if isinstance(getattr(self.__class__, key, None), cached_property):
                del self.__dict__[key]


class EC2Metadata(BaseLazyObject):

    def __init__(self, session=None):
        if session is None:
            session = requests.Session()
        self._session = session

    def _get_url(self, url, allow_404=False):
        resp = self._session.get(url, timeout=1.0)
        if resp.status_code != 404 or not allow_404:
            resp.raise_for_status()
        return resp

    @property
    def account_id(self):
        return self.instance_identity_document['accountId']

    @cached_property
    def ami_id(self):
        return self._get_url(METADATA_URL + 'ami-id').text

    @cached_property
    def availability_zone(self):
        return self._get_url(METADATA_URL + 'placement/availability-zone').text

    @cached_property
    def ami_launch_index(self):
        return int(self._get_url(METADATA_URL + 'ami-launch-index').text)

    @cached_property
    def ami_manifest_path(self):
        return self._get_url(METADATA_URL + 'ami-manifest-path').text

    @cached_property
    def iam_info(self):
        resp = self._get_url(METADATA_URL + 'iam/info', allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.json()

    @property
    def instance_action(self):
        return self._get_url(METADATA_URL + 'instance-action').text

    @cached_property
    def instance_id(self):
        return self._get_url(METADATA_URL + 'instance-id').text

    @cached_property
    def instance_identity_document(self):
        return self._get_url(DYNAMIC_URL + 'instance-identity/document').json()

    @property
    def instance_profile_arn(self):
        iam_info = self.iam_info
        if iam_info is None:
            return None
        return iam_info['InstanceProfileArn']

    @property
    def instance_profile_id(self):
        iam_info = self.iam_info
        if iam_info is None:
            return None
        return iam_info['InstanceProfileId']

    @cached_property
    def instance_type(self):
        return self._get_url(METADATA_URL + 'instance-type').text

    @cached_property
    def kernel_id(self):
        resp = self._get_url(METADATA_URL + 'kernel-id', allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def mac(self):
        return self._get_url(METADATA_URL + 'mac').text

    @cached_property
    def network_interfaces(self):
        macs_text = self._get_url(METADATA_URL + 'network/interfaces/macs/').text
        macs = [line.rstrip('/') for line in macs_text.splitlines()]
        return {mac: NetworkInterface(mac, self) for mac in macs}

    @cached_property
    def private_hostname(self):
        return self._get_url(METADATA_URL + 'local-hostname').text

    @cached_property
    def private_ipv4(self):
        return self._get_url(METADATA_URL + 'local-ipv4').text

    @cached_property
    def public_hostname(self):
        resp = self._get_url(METADATA_URL + 'public-hostname', allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def public_ipv4(self):
        resp = self._get_url(METADATA_URL + 'public-ipv4', allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def region(self):
        return self.instance_identity_document['region']

    @cached_property
    def reservation_id(self):
        return self._get_url(METADATA_URL + 'reservation-id').text

    @cached_property
    def security_groups(self):
        return self._get_url(METADATA_URL + 'security-groups').text.splitlines()

    @cached_property
    def user_data(self):
        resp = self._get_url(USERDATA_URL, allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.content


class NetworkInterface(BaseLazyObject):

    def __init__(self, mac, parent=None):
        self.mac = mac
        if parent is None:
            self.parent = ec2_metadata
        else:
            self.parent = parent

    def __repr__(self):
        return 'NetworkInterface({mac})'.format(mac=repr(self.mac))

    def __eq__(self, other):
        return (
            isinstance(other, NetworkInterface) and
            self.mac == other.mac and
            self.parent == other.parent
        )

    def _url(self, item):
        return '{base}network/interfaces/macs/{mac}/{item}'.format(
            base=METADATA_URL,
            mac=self.mac,
            item=item,
        )

    @cached_property
    def device_number(self):
        return int(self.parent._get_url(self._url('device-number')).text)

    @cached_property
    def interface_id(self):
        return self.parent._get_url(self._url('interface-id')).text

    @cached_property
    def ipv4_associations(self):
        associations = {}
        for public_ip in self.public_ipv4s:
            url = self._url('ipv4-associations/{}'.format(public_ip))
            resp = self.parent._get_url(url)
            private_ips = resp.text.splitlines()
            associations[public_ip] = private_ips
        return associations

    @cached_property
    def ipv6s(self):
        resp = self.parent._get_url(self._url('ipv6s'), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def owner_id(self):
        return self.parent._get_url(self._url('owner-id')).text

    @cached_property
    def private_hostname(self):
        return self.parent._get_url(self._url('local-hostname')).text

    @cached_property
    def private_ipv4s(self):
        return self.parent._get_url(self._url('local-ipv4s')).text.splitlines()

    @cached_property
    def public_hostname(self):
        resp = self.parent._get_url(self._url('public-hostname'), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def public_ipv4s(self):
        resp = self.parent._get_url(self._url('public-ipv4s'), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def security_groups(self):
        return self.parent._get_url(self._url('security-groups')).text.splitlines()

    @cached_property
    def security_group_ids(self):
        return self.parent._get_url(self._url('security-group-ids')).text.splitlines()

    @cached_property
    def subnet_id(self):
        return self.parent._get_url(self._url('subnet-id')).text

    @cached_property
    def subnet_ipv4_cidr_block(self):
        resp = self.parent._get_url(self._url('subnet-ipv4-cidr-block'), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def subnet_ipv6_cidr_blocks(self):
        resp = self.parent._get_url(self._url('subnet-ipv6-cidr-blocks'), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def vpc_id(self):
        return self.parent._get_url(self._url('vpc-id')).text

    @cached_property
    def vpc_ipv4_cidr_block(self):
        resp = self.parent._get_url(self._url('vpc-ipv4-cidr-block'), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def vpc_ipv4_cidr_blocks(self):
        resp = self.parent._get_url(self._url('vpc-ipv4-cidr-blocks'), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def vpc_ipv6_cidr_blocks(self):
        resp = self.parent._get_url(self._url('vpc-ipv6-cidr-blocks'), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()


ec2_metadata = EC2Metadata()
