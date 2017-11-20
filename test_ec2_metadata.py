# -*- coding:utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import json

import pytest
import requests
import responses

from ec2_metadata import DYNAMIC_URL, METADATA_URL, USERDATA_URL, NetworkInterface, ec2_metadata


@pytest.fixture(autouse=True)
def clear_it():
    ec2_metadata.clear_all()


@pytest.fixture(autouse=True)
def resps():
    with responses.RequestsMock() as resps:
        yield resps


def add_response(resps, url, text='', **kwargs):
    if url.startswith('http://'):
        full_url = url
    else:
        full_url = METADATA_URL + url
    resps.add(responses.GET, full_url, body=text, **kwargs)


example_mac = '00:11:22:33:44:55'


# EC2Metadata tests

def add_identity_doc_response(resps, overrides=None):
    identity_doc = {
        'accountId': '123456789012',
        'architecture': 'x86_64',
        'availabilityZone': 'eu-west-1a',
        'imageId': 'ami-12345678',
        'instanceId': 'i-12345678',
        'instanceType': 't2.nano',
        'privateIp': '172.30.0.0',
        'region': 'eu-west-1',
        'version': '2010-08-31',
    }
    if overrides:
        identity_doc.update(overrides)
    resps.add(
        responses.GET,
        DYNAMIC_URL + 'instance-identity/document',
        content_type='application/json',
        body=json.dumps(identity_doc),
    )
    return identity_doc


def test_account_id(resps):
    add_identity_doc_response(resps, {'accountId': '1234'})
    assert ec2_metadata.account_id == '1234'


def test_account_id_error(resps):
    add_response(resps, DYNAMIC_URL + 'instance-identity/document', status=500)
    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.account_id


def test_ami_id(resps):
    add_response(resps, 'ami-id', 'ami-12345678')
    assert ec2_metadata.ami_id == 'ami-12345678'


def test_ami_id_cached(resps):
    add_response(resps, 'ami-id', 'ami-12345678')
    ec2_metadata.ami_id
    ec2_metadata.ami_id
    assert len(resps.calls) == 1


def test_ami_id_cached_cleared(resps):
    add_response(resps, 'ami-id', 'ami-12345678')
    add_response(resps, 'ami-id', 'ami-12345678')
    ec2_metadata.ami_id

    ec2_metadata.clear_all()
    ec2_metadata.ami_id

    assert len(resps.calls) == 2


def test_ami_launch_index(resps):
    add_response(resps, 'ami-launch-index', '0')
    assert ec2_metadata.ami_launch_index == 0


def test_ami_manifest_path(resps):
    add_response(resps, 'ami-manifest-path', '(unknown)')
    assert ec2_metadata.ami_manifest_path == '(unknown)'


def test_availability_zone(resps):
    add_response(resps, 'placement/availability-zone', 'eu-west-1a')
    assert ec2_metadata.availability_zone == 'eu-west-1a'


def test_iam_info(resps):
    add_response(resps, 'iam/info', '{}')
    assert ec2_metadata.iam_info == {}


def test_iam_info_none(resps):
    add_response(resps, 'iam/info', status=404)
    assert ec2_metadata.iam_info is None


def test_iam_info_unexpected(resps):
    add_response(resps, 'iam/info', status=500)
    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.iam_info


def test_instance_action(resps):
    add_response(resps, 'instance-action', 'none')
    assert ec2_metadata.instance_action == 'none'


def test_instance_id(resps):
    add_response(resps, 'instance-id', 'i-12345678')
    assert ec2_metadata.instance_id == 'i-12345678'


def test_instance_identity(resps):
    identity_doc = add_identity_doc_response(resps)
    assert ec2_metadata.instance_identity_document == identity_doc


def test_instance_profile_arn(resps):
    add_response(resps, 'iam/info', '{"InstanceProfileArn": "arn:foobar"}')
    assert ec2_metadata.instance_profile_arn == 'arn:foobar'


def test_instance_profile_arn_none(resps):
    add_response(resps, 'iam/info', status=404)
    assert ec2_metadata.instance_profile_arn is None


def test_instance_profile_id(resps):
    add_response(resps, 'iam/info', '{"InstanceProfileId": "some-id"}')
    assert ec2_metadata.instance_profile_id == 'some-id'


def test_instance_profile_id_none(resps):
    add_response(resps, 'iam/info', status=404)
    assert ec2_metadata.instance_profile_id is None


def test_instance_type(resps):
    add_response(resps, 'instance-type', 't2.nano')
    assert ec2_metadata.instance_type == 't2.nano'


def test_kernel_id(resps):
    add_response(resps, 'kernel-id', 'aki-dc9ed9af')
    assert ec2_metadata.kernel_id == 'aki-dc9ed9af'


def test_kernel_id_none(resps):
    add_response(resps, 'kernel-id', status=404)
    assert ec2_metadata.kernel_id is None


def test_mac(resps):
    add_response(resps, 'mac', example_mac)
    assert ec2_metadata.mac == example_mac


def test_network_interfaces(resps):
    add_response(resps, 'network/interfaces/macs/', example_mac + '/')
    assert ec2_metadata.network_interfaces == {example_mac: NetworkInterface(example_mac, ec2_metadata)}


def test_private_hostname(resps):
    add_response(resps, 'local-hostname', 'ip-172-30-0-0.eu-west-1.compute.internal')
    assert ec2_metadata.private_hostname == 'ip-172-30-0-0.eu-west-1.compute.internal'


def test_private_ipv4(resps):
    add_response(resps, 'local-ipv4', '172.30.0.0')
    assert ec2_metadata.private_ipv4 == '172.30.0.0'


def test_public_hostname(resps):
    add_response(resps, 'public-hostname', 'ec2-1-2-3-4.compute-1.amazonaws.com')
    assert ec2_metadata.public_hostname == 'ec2-1-2-3-4.compute-1.amazonaws.com'


def test_public_hostname_none(resps):
    add_response(resps, 'public-hostname', status=404)
    assert ec2_metadata.public_hostname is None


def test_public_ipv4(resps):
    add_response(resps, 'public-ipv4', '1.2.3.4')
    assert ec2_metadata.public_ipv4 == '1.2.3.4'


def test_public_ipv4_none(resps):
    add_response(resps, 'public-ipv4', status=404)
    assert ec2_metadata.public_ipv4 is None


def test_region(resps):
    add_identity_doc_response(resps, {'region': 'eu-whatever-1'})
    assert ec2_metadata.region == 'eu-whatever-1'


def test_reservation_id(resps):
    add_response(resps, 'reservation-id', 'r-12345678901234567')
    assert ec2_metadata.reservation_id == 'r-12345678901234567'


def test_security_groups_single(resps):
    # most common case: a single SG
    add_response(resps, 'security-groups', 'security-group-one')
    assert ec2_metadata.security_groups == ['security-group-one']


def test_security_groups_two(resps):
    # another common case: multiple SGs
    add_response(resps, 'security-groups', "security-group-one\nsecurity-group-2")
    assert ec2_metadata.security_groups == ['security-group-one', 'security-group-2']


def test_security_groups_emptystring(resps):
    # check '' too. Can't create an instance without a SG but we should safely handle it,
    # perhaps it's possible in OpenStack.
    add_response(resps, 'security-groups', '')
    assert ec2_metadata.security_groups == []


def test_user_data_none(resps):
    add_response(resps, USERDATA_URL, '', status=404)
    assert ec2_metadata.user_data is None


def test_user_data_something(resps):
    add_response(resps, USERDATA_URL, b'foobar')
    assert ec2_metadata.user_data == b'foobar'


# NetworkInterface tests

def add_interface_response(resps, url, text='', **kwargs):
    full_url = METADATA_URL + 'network/interfaces/macs/' + example_mac + url
    resps.add(responses.GET, full_url, body=text, **kwargs)


def test_network_interface_equal():
    assert NetworkInterface('a') == NetworkInterface('a')


def test_network_interface_not_equal():
    assert NetworkInterface('a') != NetworkInterface('b')


def test_network_interface_not_equal_class():
    assert NetworkInterface('a') != 'a'


def test_network_interface_repr():
    assert "'abc'" in repr(NetworkInterface('abc'))


def test_network_interface_device_number(resps):
    add_interface_response(resps, '/device-number', '0')
    assert NetworkInterface(example_mac).device_number == 0


def test_network_interface_ipv4_associations(resps):
    add_interface_response(resps, '/public-ipv4s', '54.0.0.0\n54.0.0.1')
    add_interface_response(resps, '/ipv4-associations/54.0.0.0', '172.30.0.0')
    add_interface_response(resps, '/ipv4-associations/54.0.0.1', '172.30.0.1')
    assert NetworkInterface(example_mac).ipv4_associations == {
        '54.0.0.0': ['172.30.0.0'],
        '54.0.0.1': ['172.30.0.1'],
    }


def test_network_interface_ipv6s(resps):
    add_interface_response(resps, '/ipv6s', '2001:db8:abcd:ef00:cbe5:798:aa26:169b\n2001:db8:abcd:ef00::f')
    assert NetworkInterface(example_mac).ipv6s == ['2001:db8:abcd:ef00:cbe5:798:aa26:169b', '2001:db8:abcd:ef00::f']


def test_network_interface_ipv6s_none(resps):
    add_interface_response(resps, '/ipv6s', status=404)
    assert NetworkInterface(example_mac).ipv6s == []


def test_network_interface_owner_id(resps):
    add_interface_response(resps, '/owner-id', '123456789012')
    assert NetworkInterface(example_mac).owner_id == '123456789012'


def test_network_interface_private_hostname(resps):
    add_interface_response(resps, '/local-hostname', 'ip-172-30-0-0.eu-west-1.compute.internal')
    assert NetworkInterface(example_mac).private_hostname == 'ip-172-30-0-0.eu-west-1.compute.internal'


def test_network_interface_private_ipv4s(resps):
    add_interface_response(resps, '/local-ipv4s', '172.30.0.0\n172.30.0.1')
    assert NetworkInterface(example_mac).private_ipv4s == ['172.30.0.0', '172.30.0.1']


def test_network_interface_public_hostname(resps):
    add_interface_response(resps, '/public-hostname', '')
    assert NetworkInterface(example_mac).public_hostname == ''


def test_network_interface_public_hostname_none(resps):
    add_interface_response(resps, '/public-hostname', status=404)
    assert NetworkInterface(example_mac).public_hostname is None


def test_network_interface_public_ipv4s(resps):
    add_interface_response(resps, '/public-ipv4s', '54.0.0.0\n54.0.0.1')
    assert NetworkInterface(example_mac).public_ipv4s == ['54.0.0.0', '54.0.0.1']


def test_network_interface_public_ipv4s_empty(resps):
    add_interface_response(resps, '/public-ipv4s', status=404)
    assert NetworkInterface(example_mac).public_ipv4s == []


def test_network_interface_security_groups(resps):
    add_interface_response(resps, '/security-groups', 'foo\nbar')
    assert NetworkInterface(example_mac).security_groups == ['foo', 'bar']


def test_network_interface_security_group_ids(resps):
    add_interface_response(resps, '/security-group-ids', 'sg-12345678\nsg-12345679')
    assert NetworkInterface(example_mac).security_group_ids == ['sg-12345678', 'sg-12345679']


def test_network_interface_subnet_id(resps):
    add_interface_response(resps, '/subnet-id', 'subnet-12345678')
    assert NetworkInterface(example_mac).subnet_id == 'subnet-12345678'


def test_network_interface_subnet_ipv4_cidr_block(resps):
    add_interface_response(resps, '/subnet-ipv4-cidr-block', '172.30.0.0/24')
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block == '172.30.0.0/24'


def test_network_interface_subnet_ipv4_cidr_block_none(resps):
    add_interface_response(resps, '/subnet-ipv4-cidr-block', status=404)
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block is None


def test_network_interface_subnet_ipv6_cidr_blocks(resps):
    add_interface_response(resps, '/subnet-ipv6-cidr-blocks', '2001:db8:abcd:ef00::/64')
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == ['2001:db8:abcd:ef00::/64']


def test_network_interface_subnet_ipv6_cidr_blocks_none(resps):
    add_interface_response(resps, '/subnet-ipv6-cidr-blocks', status=404)
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == []


def test_network_interface_vpc_id(resps):
    add_interface_response(resps, '/vpc-id', 'vpc-12345678')
    assert NetworkInterface(example_mac).vpc_id == 'vpc-12345678'


def test_network_interface_vpc_ipv4_cidr_block(resps):
    add_interface_response(resps, '/vpc-ipv4-cidr-block', '172.30.0.0/16')
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block == '172.30.0.0/16'


def test_network_interface_vpc_ipv4_cidr_block_none(resps):
    add_interface_response(resps, '/vpc-ipv4-cidr-block', status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block is None


def test_network_interface_vpc_ipv4_cidr_blocks(resps):
    add_interface_response(resps, '/vpc-ipv4-cidr-blocks', '172.30.0.0/16')
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == ['172.30.0.0/16']


def test_network_interface_vpc_ipv4_cidr_blocks_none(resps):
    add_interface_response(resps, '/vpc-ipv4-cidr-blocks', status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == []


def test_network_interface_vpc_ipv6_cidr_blocks(resps):
    add_interface_response(resps, '/vpc-ipv6-cidr-blocks', '2001:db8:abcd:ef00::/56')
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == ['2001:db8:abcd:ef00::/56']


def test_network_interface_vpc_ipv6_cidr_blocks_none(resps):
    add_interface_response(resps, '/vpc-ipv6-cidr-blocks', status=404)
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == []
