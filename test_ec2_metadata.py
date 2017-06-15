# -*- coding:utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import json

import pytest
import responses

from ec2_metadata import DYNAMIC_URL, METADATA_URL, ec2_metadata


@pytest.fixture(autouse=True)
def clear_it():
    ec2_metadata.clear_all()


@pytest.fixture(autouse=True)
def resps():
    with responses.RequestsMock() as resps:
        yield resps


def add_response(resps, url, text):
    resps.add(responses.GET, METADATA_URL + url, body=text)


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


def test_hostname(resps):
    add_response(resps, 'hostname', 'ip-172-30-0-0.eu-west-1.compute.internal')
    assert ec2_metadata.hostname == 'ip-172-30-0-0.eu-west-1.compute.internal'


def test_instance_id(resps):
    add_response(resps, 'instance-id', 'i-12345678')
    assert ec2_metadata.instance_id == 'i-12345678'


def test_instance_identity(resps):
    identity_doc = add_identity_doc_response(resps)
    assert ec2_metadata.instance_identity_document == identity_doc


def test_instance_type(resps):
    add_response(resps, 'instance-type', 't2.nano')
    assert ec2_metadata.instance_type == 't2.nano'


def test_mac(resps):
    add_response(resps, 'mac', '0a:d2:ae:4d:f3:12')
    assert ec2_metadata.mac == '0a:d2:ae:4d:f3:12'


def test_private_hostname(resps):
    add_response(resps, 'local-hostname', 'ip-172-30-0-0.eu-west-1.compute.internal')
    assert ec2_metadata.private_hostname == 'ip-172-30-0-0.eu-west-1.compute.internal'


def test_private_ipv4(resps):
    add_response(resps, 'local-ipv4', '172.30.0.0')
    assert ec2_metadata.private_ipv4 == '172.30.0.0'


def test_public_hostname(resps):
    add_response(resps, 'public-hostname', 'ec2-1-2-3-4.compute-1.amazonaws.com')
    assert ec2_metadata.public_hostname == 'ec2-1-2-3-4.compute-1.amazonaws.com'


def test_public_ipv4(resps):
    add_response(resps, 'public-ipv4', '1.2.3.4')
    assert ec2_metadata.public_ipv4 == '1.2.3.4'


def test_region(resps):
    add_identity_doc_response(resps, {'region': 'eu-whatever-1'})
    assert ec2_metadata.region == 'eu-whatever-1'


def test_reservation_id(resps):
    add_response(resps, 'reservation-id', 'r-12345678901234567')
    assert ec2_metadata.reservation_id == 'r-12345678901234567'
