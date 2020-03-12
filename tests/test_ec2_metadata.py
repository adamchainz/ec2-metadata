import pytest
import requests

from ec2_metadata import (
    DYNAMIC_URL,
    METADATA_URL,
    SERVICE_URL,
    TOKEN_TTL_SECONDS,
    USERDATA_URL,
    NetworkInterface,
    ec2_metadata,
)


@pytest.fixture(autouse=True)
def clear_it():
    ec2_metadata.clear_all()


@pytest.fixture(autouse=True)
def em_requests_mock(requests_mock):
    requests_mock.put(
        SERVICE_URL + "api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(TOKEN_TTL_SECONDS)},
        text="example-token",
    )
    yield requests_mock


example_mac = "00:11:22:33:44:55"


# EC2Metadata tests


def add_identity_doc_response(em_requests_mock, overrides=None):
    identity_doc = {
        "accountId": "123456789012",
        "architecture": "x86_64",
        "availabilityZone": "eu-west-1a",
        "imageId": "ami-12345678",
        "instanceId": "i-12345678",
        "instanceType": "t2.nano",
        "privateIp": "172.30.0.0",
        "region": "eu-west-1",
        "version": "2010-08-31",
    }
    if overrides:
        identity_doc.update(overrides)
    em_requests_mock.get(DYNAMIC_URL + "instance-identity/document", json=identity_doc)
    return identity_doc


def test_account_id(em_requests_mock):
    add_identity_doc_response(em_requests_mock, {"accountId": "1234"})
    assert ec2_metadata.account_id == "1234"


def test_account_id_token_error(requests_mock):
    requests_mock.put(
        SERVICE_URL + "api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(TOKEN_TTL_SECONDS)},
        status_code=500,
    )
    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.account_id


def test_account_id_error(em_requests_mock):
    em_requests_mock.get(DYNAMIC_URL + "instance-identity/document", status_code=500)
    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.account_id


def test_ami_id(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "ami-id", text="ami-12345678")
    assert ec2_metadata.ami_id == "ami-12345678"


def test_ami_id_cached(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "ami-id", text="ami-12345678")
    ec2_metadata.ami_id
    em_requests_mock.get(METADATA_URL + "ami-id", status_code=500)
    ec2_metadata.ami_id  # no error


def test_ami_id_cached_cleared(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "ami-id", text="ami-12345678")
    ec2_metadata.ami_id

    ec2_metadata.clear_all()
    em_requests_mock.get(METADATA_URL + "ami-id", status_code=500)

    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.ami_id


def test_ami_launch_index(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "ami-launch-index", text="0")
    assert ec2_metadata.ami_launch_index == 0


def test_ami_manifest_path(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "ami-manifest-path", text="(unknown)")
    assert ec2_metadata.ami_manifest_path == "(unknown)"


def test_availability_zone(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "placement/availability-zone", text="eu-west-1a"
    )
    assert ec2_metadata.availability_zone == "eu-west-1a"


def test_iam_info(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "iam/info", text="{}")
    assert ec2_metadata.iam_info == {}


def test_iam_info_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "iam/info", status_code=404)
    assert ec2_metadata.iam_info is None


def test_iam_info_unexpected(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "iam/info", status_code=500)
    with pytest.raises(requests.exceptions.HTTPError):
        ec2_metadata.iam_info


def test_instance_action(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "instance-action", text="none")
    assert ec2_metadata.instance_action == "none"


def test_instance_id(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "instance-id", text="i-12345678")
    assert ec2_metadata.instance_id == "i-12345678"


def test_instance_identity(em_requests_mock):
    identity_doc = add_identity_doc_response(em_requests_mock)
    assert ec2_metadata.instance_identity_document == identity_doc


def test_instance_profile_arn(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "iam/info", text='{"InstanceProfileArn": "arn:foobar"}'
    )
    assert ec2_metadata.instance_profile_arn == "arn:foobar"


def test_instance_profile_arn_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "iam/info", status_code=404)
    assert ec2_metadata.instance_profile_arn is None


def test_instance_profile_id(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "iam/info", text='{"InstanceProfileId": "some-id"}'
    )
    assert ec2_metadata.instance_profile_id == "some-id"


def test_instance_profile_id_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "iam/info", status_code=404)
    assert ec2_metadata.instance_profile_id is None


def test_instance_type(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "instance-type", text="t2.nano")
    assert ec2_metadata.instance_type == "t2.nano"


def test_kernel_id(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "kernel-id", text="aki-dc9ed9af")
    assert ec2_metadata.kernel_id == "aki-dc9ed9af"


def test_kernel_id_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "kernel-id", status_code=404)
    assert ec2_metadata.kernel_id is None


def test_mac(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "mac", text=example_mac)
    assert ec2_metadata.mac == example_mac


def test_network_interfaces(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "network/interfaces/macs/", text=example_mac + "/"
    )
    assert ec2_metadata.network_interfaces == {
        example_mac: NetworkInterface(example_mac, ec2_metadata)
    }


def test_private_hostname(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "local-hostname", text="ip-172-30-0-0.eu-west-1.compute.internal"
    )
    assert ec2_metadata.private_hostname == "ip-172-30-0-0.eu-west-1.compute.internal"


def test_private_ipv4(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "local-ipv4", text="172.30.0.0")
    assert ec2_metadata.private_ipv4 == "172.30.0.0"


def test_public_hostname(em_requests_mock):
    em_requests_mock.get(
        METADATA_URL + "public-hostname", text="ec2-1-2-3-4.compute-1.amazonaws.com"
    )
    assert ec2_metadata.public_hostname == "ec2-1-2-3-4.compute-1.amazonaws.com"


def test_public_hostname_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "public-hostname", status_code=404)
    assert ec2_metadata.public_hostname is None


def test_public_ipv4(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "public-ipv4", text="1.2.3.4")
    assert ec2_metadata.public_ipv4 == "1.2.3.4"


def test_public_ipv4_none(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "public-ipv4", status_code=404)
    assert ec2_metadata.public_ipv4 is None


def test_region(em_requests_mock):
    add_identity_doc_response(em_requests_mock, {"region": "eu-whatever-1"})
    assert ec2_metadata.region == "eu-whatever-1"


def test_reservation_id(em_requests_mock):
    em_requests_mock.get(METADATA_URL + "reservation-id", text="r-12345678901234567")
    assert ec2_metadata.reservation_id == "r-12345678901234567"


def test_security_groups_single(em_requests_mock):
    # most common case: a single SG
    em_requests_mock.get(METADATA_URL + "security-groups", text="security-group-one")
    assert ec2_metadata.security_groups == ["security-group-one"]


def test_security_groups_two(em_requests_mock):
    # another common case: multiple SGs
    em_requests_mock.get(
        METADATA_URL + "security-groups", text="security-group-one\nsecurity-group-2"
    )
    assert ec2_metadata.security_groups == ["security-group-one", "security-group-2"]


def test_security_groups_emptystring(em_requests_mock):
    # Check '' too. Can't create an instance without a SG on EC2 but we should
    # safely handle it, perhaps it's possible in e.g. OpenStack.
    em_requests_mock.get(METADATA_URL + "security-groups", text="")
    assert ec2_metadata.security_groups == []


def test_user_data_none(em_requests_mock):
    em_requests_mock.get(USERDATA_URL, status_code=404)
    assert ec2_metadata.user_data is None


def test_user_data_something(em_requests_mock):
    em_requests_mock.get(USERDATA_URL, content=b"foobar")
    assert ec2_metadata.user_data == b"foobar"


# NetworkInterface tests


def add_interface_response(em_requests_mock, url, text="", **kwargs):
    full_url = METADATA_URL + "network/interfaces/macs/" + example_mac + url
    em_requests_mock.get(full_url, text=text, **kwargs)


def test_network_interface_equal():
    assert NetworkInterface("a") == NetworkInterface("a")


def test_network_interface_not_equal():
    assert NetworkInterface("a") != NetworkInterface("b")


def test_network_interface_not_equal_class():
    assert NetworkInterface("a") != "a"


def test_network_interface_repr():
    assert "'abc'" in repr(NetworkInterface("abc"))


def test_network_interface_device_number(em_requests_mock):
    add_interface_response(em_requests_mock, "/device-number", "0")
    assert NetworkInterface(example_mac).device_number == 0


def test_network_interface_interface_id(em_requests_mock):
    add_interface_response(em_requests_mock, "/interface-id", "eni-12345")
    assert NetworkInterface(example_mac).interface_id == "eni-12345"


def test_network_interface_ipv4_associations(em_requests_mock):
    add_interface_response(em_requests_mock, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    add_interface_response(
        em_requests_mock, "/ipv4-associations/54.0.0.0", "172.30.0.0"
    )
    add_interface_response(
        em_requests_mock, "/ipv4-associations/54.0.0.1", "172.30.0.1"
    )
    assert NetworkInterface(example_mac).ipv4_associations == {
        "54.0.0.0": ["172.30.0.0"],
        "54.0.0.1": ["172.30.0.1"],
    }


def test_network_interface_ipv6s(em_requests_mock):
    add_interface_response(
        em_requests_mock,
        "/ipv6s",
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b\n2001:db8:abcd:ef00::f",
    )
    assert NetworkInterface(example_mac).ipv6s == [
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b",
        "2001:db8:abcd:ef00::f",
    ]


def test_network_interface_ipv6s_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/ipv6s", status_code=404)
    assert NetworkInterface(example_mac).ipv6s == []


def test_network_interface_owner_id(em_requests_mock):
    add_interface_response(em_requests_mock, "/owner-id", "123456789012")
    assert NetworkInterface(example_mac).owner_id == "123456789012"


def test_network_interface_private_hostname(em_requests_mock):
    add_interface_response(
        em_requests_mock, "/local-hostname", "ip-172-30-0-0.eu-west-1.compute.internal"
    )
    assert (
        NetworkInterface(example_mac).private_hostname
        == "ip-172-30-0-0.eu-west-1.compute.internal"
    )


def test_network_interface_private_ipv4s(em_requests_mock):
    add_interface_response(em_requests_mock, "/local-ipv4s", "172.30.0.0\n172.30.0.1")
    assert NetworkInterface(example_mac).private_ipv4s == ["172.30.0.0", "172.30.0.1"]


def test_network_interface_public_hostname(em_requests_mock):
    add_interface_response(em_requests_mock, "/public-hostname", "")
    assert NetworkInterface(example_mac).public_hostname == ""


def test_network_interface_public_hostname_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/public-hostname", status_code=404)
    assert NetworkInterface(example_mac).public_hostname is None


def test_network_interface_public_ipv4s(em_requests_mock):
    add_interface_response(em_requests_mock, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    assert NetworkInterface(example_mac).public_ipv4s == ["54.0.0.0", "54.0.0.1"]


def test_network_interface_public_ipv4s_empty(em_requests_mock):
    add_interface_response(em_requests_mock, "/public-ipv4s", status_code=404)
    assert NetworkInterface(example_mac).public_ipv4s == []


def test_network_interface_security_groups(em_requests_mock):
    add_interface_response(em_requests_mock, "/security-groups", "foo\nbar")
    assert NetworkInterface(example_mac).security_groups == ["foo", "bar"]


def test_network_interface_security_group_ids(em_requests_mock):
    add_interface_response(
        em_requests_mock, "/security-group-ids", "sg-12345678\nsg-12345679"
    )
    assert NetworkInterface(example_mac).security_group_ids == [
        "sg-12345678",
        "sg-12345679",
    ]


def test_network_interface_subnet_id(em_requests_mock):
    add_interface_response(em_requests_mock, "/subnet-id", "subnet-12345678")
    assert NetworkInterface(example_mac).subnet_id == "subnet-12345678"


def test_network_interface_subnet_ipv4_cidr_block(em_requests_mock):
    add_interface_response(em_requests_mock, "/subnet-ipv4-cidr-block", "172.30.0.0/24")
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block == "172.30.0.0/24"


def test_network_interface_subnet_ipv4_cidr_block_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/subnet-ipv4-cidr-block", status_code=404)
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block is None


def test_network_interface_subnet_ipv6_cidr_blocks(em_requests_mock):
    add_interface_response(
        em_requests_mock, "/subnet-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/64"
    )
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/64"
    ]


def test_network_interface_subnet_ipv6_cidr_blocks_none(em_requests_mock):
    add_interface_response(
        em_requests_mock, "/subnet-ipv6-cidr-blocks", status_code=404
    )
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == []


def test_network_interface_vpc_id(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-id", "vpc-12345678")
    assert NetworkInterface(example_mac).vpc_id == "vpc-12345678"


def test_network_interface_vpc_ipv4_cidr_block(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-ipv4-cidr-block", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block == "172.30.0.0/16"


def test_network_interface_vpc_ipv4_cidr_block_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-ipv4-cidr-block", status_code=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block is None


def test_network_interface_vpc_ipv4_cidr_blocks(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-ipv4-cidr-blocks", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == ["172.30.0.0/16"]


def test_network_interface_vpc_ipv4_cidr_blocks_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-ipv4-cidr-blocks", status_code=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == []


def test_network_interface_vpc_ipv6_cidr_blocks(em_requests_mock):
    add_interface_response(
        em_requests_mock, "/vpc-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/56"
    )
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/56"
    ]


def test_network_interface_vpc_ipv6_cidr_blocks_none(em_requests_mock):
    add_interface_response(em_requests_mock, "/vpc-ipv6-cidr-blocks", status_code=404)
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == []
