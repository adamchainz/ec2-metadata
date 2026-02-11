from __future__ import annotations

import datetime as dt
import json
from collections.abc import Generator
from io import BytesIO
from typing import Any
from unittest.mock import Mock

import pytest
import urllib3
from urllib3 import HTTPResponse
from urllib3.exceptions import HTTPError

from ec2_metadata import (
    EC2Metadata,
    InstanceIdentityDocumentDict,
    NetworkInterface,
    PublicKey,
    ec2_metadata,
)


@pytest.fixture(autouse=True)
def clear_it():
    ec2_metadata.clear_all()


def make_response(*, status: int = 200, body: bytes = b"") -> HTTPResponse:
    return HTTPResponse(status=status, body=BytesIO(body))


@pytest.fixture(autouse=True)
def mock_pool(monkeypatch: pytest.MonkeyPatch) -> Generator[Mock]:
    mock_pm = Mock(spec=urllib3.PoolManager)
    responses: dict[tuple[str, str], HTTPResponse] = {}

    def request_side_effect(method: str, url: str, **kwargs: Any) -> HTTPResponse:
        return responses[(method, url)]

    mock_pm.request.side_effect = request_side_effect
    mock_pm._responses = responses

    token_resp = make_response(body=b"example-token")
    responses[("PUT", "http://169.254.169.254/latest/api/token")] = token_resp

    monkeypatch.setattr(ec2_metadata, "_pool_manager", mock_pm)
    yield mock_pm


example_mac = "00:11:22:33:44:55"
example_public_key = "ssh-rsa AAAAblahblahblah= exampleuser@examplehost\n"

# EC2Metadata tests


def test_custom_session(mock_pool):
    EC2Metadata(pool_manager=urllib3.PoolManager())
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        make_response(body=b"ami-12345678")
    )
    assert ec2_metadata.ami_id == "ami-12345678"


def add_identity_doc_response(
    mock_pool: Mock,
    account_id: str = "123456789012",
    region: str = "eu-west-1",
) -> InstanceIdentityDocumentDict:
    identity_doc: InstanceIdentityDocumentDict = {
        "accountId": account_id,
        "architecture": "x86_64",
        "availabilityZone": "eu-west-1a",
        "billingProducts": None,
        "imageId": "ami-12345678",
        "instanceId": "i-12345678",
        "instanceType": "t2.nano",
        "kernelId": None,
        "marketplaceProductCodes": None,
        "pendingTime": "2022-08-12T10:22:28Z",
        "privateIp": "172.30.0.0",
        "ramdiskId": None,
        "region": region,
        "version": "2010-08-31",
    }
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/dynamic/instance-identity/document")
    ] = HTTPResponse(body=json.dumps(identity_doc).encode())
    return identity_doc


def test_account_id(mock_pool):
    add_identity_doc_response(mock_pool, account_id="1234")
    assert ec2_metadata.account_id == "1234"


def test_account_id_token_error(mock_pool):
    mock_pool._responses[("PUT", "http://169.254.169.254/latest/api/token")] = (
        HTTPResponse(status=500, body=b"")
    )
    with pytest.raises(HTTPError):
        ec2_metadata.account_id  # noqa: B018


def test_account_id_error(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/dynamic/instance-identity/document")
    ] = HTTPResponse(status=500, body=b"")
    with pytest.raises(HTTPError):
        ec2_metadata.account_id  # noqa: B018


def test_ami_id(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        make_response(body=b"ami-12345678")
    )
    assert ec2_metadata.ami_id == "ami-12345678"


def test_ami_id_cached(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        make_response(body=b"ami-12345678")
    )
    ec2_metadata.ami_id  # noqa: B018
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        HTTPResponse(status=500, body=b"")
    )
    ec2_metadata.ami_id  # noqa: B018 - no error


def test_ami_id_cached_cleared(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        make_response(body=b"ami-12345678")
    )
    ec2_metadata.ami_id  # noqa: B018

    ec2_metadata.clear_all()
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] = (
        HTTPResponse(status=500, body=b"")
    )

    with pytest.raises(HTTPError):
        ec2_metadata.ami_id  # noqa: B018


def test_ami_launch_index(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/ami-launch-index")
    ] = make_response(body=b"0")
    assert ec2_metadata.ami_launch_index == 0


def test_ami_manifest_path(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/ami-manifest-path")
    ] = make_response(body=b"(unknown)")
    assert ec2_metadata.ami_manifest_path == "(unknown)"


def test_autoscaling_target_lifecycle_state_none(mock_pool):
    mock_pool._responses[
        (
            "GET",
            "http://169.254.169.254/latest/meta-data/autoscaling/target-lifecycle-state",
        )
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.autoscaling_target_lifecycle_state is None


def test_autoscaling_target_lifecycle_state_in_service(mock_pool):
    mock_pool._responses[
        (
            "GET",
            "http://169.254.169.254/latest/meta-data/autoscaling/target-lifecycle-state",
        )
    ] = make_response(body=b"InService")
    assert ec2_metadata.autoscaling_target_lifecycle_state == "InService"


def test_availability_zone(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/placement/availability-zone")
    ] = make_response(body=b"eu-west-1a")
    assert ec2_metadata.availability_zone == "eu-west-1a"


def test_availability_zone_id(mock_pool):
    mock_pool._responses[
        (
            "GET",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone-id",
        )
    ] = make_response(body=b"use1-az6")
    assert ec2_metadata.availability_zone_id == "use1-az6"


def test_availability_zone_id_none(mock_pool):
    mock_pool._responses[
        (
            "GET",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone-id",
        )
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.availability_zone_id is None


def test_domain(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/services/domain")
    ] = make_response(body=b"amazonaws.com")
    assert ec2_metadata.domain == "amazonaws.com"


def test_iam_info(mock_pool):
    result = {
        "InstanceProfileArn": "arn:foobar/myInstanceProfile",
        "InstanceProfileId": "some-id",
        "LastUpdated": "2022-08-12T10:22:29Z",
    }
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = make_response(body=json.dumps(result).encode())
    assert ec2_metadata.iam_info == result


def test_iam_info_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.iam_info is None


def test_iam_info_unexpected(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(status=500, body=b"")
    with pytest.raises(HTTPError):
        ec2_metadata.iam_info  # noqa: B018


def test_iam_security_credentials(mock_pool):
    profile = "myInstanceProfile"
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(
        status=200,
        body=json.dumps({"InstanceProfileArn": f"arn:foobar/{profile}"}).encode(),
    )
    result = {
        "LastUpdated": "2022-08-12T10:48:52Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "some-access-key-id",
        "SecretAccessKey": "some-secret-access-key",
        "Token": "some-token",
        "Expiration": "2022-08-12T17:03:05Z",
    }
    mock_pool._responses[
        (
            "GET",
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile}",
        )
    ] = make_response(body=json.dumps(result).encode())
    assert ec2_metadata.iam_security_credentials == result


def test_iam_security_credentials_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.iam_security_credentials is None


def test_instance_action(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/instance-action")
    ] = make_response(body=b"none")
    assert ec2_metadata.instance_action == "none"


def test_instance_id(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/instance-id")
    ] = make_response(body=b"i-12345678")
    assert ec2_metadata.instance_id == "i-12345678"


def test_instance_identity(mock_pool):
    identity_doc = add_identity_doc_response(mock_pool)
    assert ec2_metadata.instance_identity_document == identity_doc


def test_instance_life_cycle(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/instance-life-cycle")
    ] = make_response(body=b"on-demand")
    assert ec2_metadata.instance_life_cycle == "on-demand"


def test_instance_profile_arn(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(
        status=200,
        body=b'{"InstanceProfileArn": "arn:foobar/myInstanceProfile"}',
    )
    assert ec2_metadata.instance_profile_arn == "arn:foobar/myInstanceProfile"


def test_instance_profile_arn_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.instance_profile_arn is None


def test_instance_profile_id(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(
        status=200,
        body=b'{"InstanceProfileId": "some-id"}',
    )
    assert ec2_metadata.instance_profile_id == "some-id"


def test_instance_profile_id_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.instance_profile_id is None


def test_instance_profile_name(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/iam/info")
    ] = HTTPResponse(
        status=200,
        body=b'{"InstanceProfileArn": "arn:foobar/myInstanceProfile"}',
    )
    assert ec2_metadata.instance_profile_name == "myInstanceProfile"


def test_instance_type(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/instance-type")
    ] = make_response(body=b"t2.nano")
    assert ec2_metadata.instance_type == "t2.nano"


def test_kernel_id(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/kernel-id")
    ] = make_response(body=b"aki-dc9ed9af")
    assert ec2_metadata.kernel_id == "aki-dc9ed9af"


def test_kernel_id_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/kernel-id")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.kernel_id is None


def test_mac(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/meta-data/mac")] = (
        make_response(body=example_mac.encode())
    )
    assert ec2_metadata.mac == example_mac


def test_network_interfaces(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/network/interfaces/macs/")
    ] = make_response(body=f"{example_mac}/".encode())
    assert ec2_metadata.network_interfaces == {
        example_mac: NetworkInterface(example_mac, ec2_metadata)
    }


def test_partition(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/services/partition")
    ] = make_response(body=b"aws")
    assert ec2_metadata.partition == "aws"


def test_private_hostname(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/local-hostname")
    ] = HTTPResponse(
        status=200,
        body=b"ip-172-30-0-0.eu-west-1.compute.internal",
    )
    assert ec2_metadata.private_hostname == "ip-172-30-0-0.eu-west-1.compute.internal"


def test_private_ipv4(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/local-ipv4")
    ] = make_response(body=b"172.30.0.0")
    assert ec2_metadata.private_ipv4 == "172.30.0.0"


def test_public_hostname(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-hostname")
    ] = HTTPResponse(
        status=200,
        body=b"ec2-1-2-3-4.compute-1.amazonaws.com",
    )
    assert ec2_metadata.public_hostname == "ec2-1-2-3-4.compute-1.amazonaws.com"


def test_public_hostname_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-hostname")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.public_hostname is None


def test_public_ipv4(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-ipv4")
    ] = make_response(body=b"1.2.3.4")
    assert ec2_metadata.public_ipv4 == "1.2.3.4"


def test_public_ipv4_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-ipv4")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.public_ipv4 is None


def test_public_keys(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-keys/")
    ] = make_response(body=b"0=somekey")
    assert ec2_metadata.public_keys == {"somekey": PublicKey(0, ec2_metadata)}


def test_public_keys_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/public-keys/")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.public_keys == {}


def test_region(mock_pool):
    add_identity_doc_response(mock_pool, region="eu-whatever-1")
    assert ec2_metadata.region == "eu-whatever-1"


def test_reservation_id(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/reservation-id")
    ] = make_response(body=b"r-12345678901234567")
    assert ec2_metadata.reservation_id == "r-12345678901234567"


def test_security_groups_single(mock_pool):
    # most common case: a single SG
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/security-groups")
    ] = make_response(body=b"security-group-one")
    assert ec2_metadata.security_groups == ["security-group-one"]


def test_security_groups_two(mock_pool):
    # another common case: multiple SGs
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/security-groups")
    ] = HTTPResponse(
        status=200,
        body=b"security-group-one\nsecurity-group-2",
    )
    assert ec2_metadata.security_groups == ["security-group-one", "security-group-2"]


def test_security_groups_emptystring(mock_pool):
    # Check '' too. Can't create an instance without a SG on EC2 but we should
    # safely handle it, perhaps it's possible in e.g. OpenStack.
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/security-groups")
    ] = make_response(body=b"")
    assert ec2_metadata.security_groups == []


def test_spot_instance_action_none(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/spot/instance-action")
    ] = HTTPResponse(status=404, body=b"")
    assert ec2_metadata.spot_instance_action is None


def test_spot_instance_action(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/spot/instance-action")
    ] = HTTPResponse(
        status=200,
        body=b'{"action": "stop", "time": "2017-09-18T08:22:00Z"}',
    )
    sia = ec2_metadata.spot_instance_action
    assert sia is not None
    assert sia.action == "stop"
    assert sia.time == dt.datetime(2017, 9, 18, 8, 22, 0, tzinfo=dt.timezone.utc)


def test_tags_not_enabled(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = HTTPResponse(status=404, body=b"")
    with pytest.raises(HTTPError):
        ec2_metadata.tags  # noqa: B018


def test_tags_empty(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"")
    assert dict(ec2_metadata.tags) == {}


def test_tags_one(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"Name")
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/Name")
    ] = make_response(body=b"test-instance")

    assert dict(ec2_metadata.tags) == {"Name": "test-instance"}


def test_tags_multiple(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"Name\ncustom-tag")
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/Name")
    ] = make_response(body=b"test-instance")
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/custom-tag")
    ] = make_response(body=b"custom-value")

    assert dict(ec2_metadata.tags) == {
        "Name": "test-instance",
        "custom-tag": "custom-value",
    }


def test_tags_repeat_access(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"Name")
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/Name")
    ] = make_response(body=b"test-instance")

    ec2_metadata.tags["Name"]
    ec2_metadata.tags["Name"]

    # 3 requests: api/token, tags/instance, tags/instance/Name
    assert mock_pool.request.call_count == 3


def test_tags_iter(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"Name")

    assert list(iter(ec2_metadata.tags)) == ["Name"]


def test_tags_len(mock_pool):
    mock_pool._responses[
        ("GET", "http://169.254.169.254/latest/meta-data/tags/instance/")
    ] = make_response(body=b"Name\ncustom-tag")

    assert len(ec2_metadata.tags) == 2


def test_user_data_none(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/user-data/")] = (
        HTTPResponse(status=404, body=b"")
    )
    assert ec2_metadata.user_data is None


def test_user_data_something(mock_pool):
    mock_pool._responses[("GET", "http://169.254.169.254/latest/user-data/")] = (
        make_response(body=b"foobar")
    )
    assert ec2_metadata.user_data == b"foobar"


# NetworkInterface tests


def add_interface_response(
    mock_pool: Mock, url: str, text: str = "", status: int = 200, **kwargs: Any
) -> None:
    full_url = f"http://169.254.169.254/latest/meta-data/network/interfaces/macs/{example_mac}{url}"
    mock_pool._responses[("GET", full_url)] = make_response(
        status=status, body=text.encode()
    )


def test_network_interface_equal():
    assert NetworkInterface("a") == NetworkInterface("a")


def test_network_interface_not_equal():
    assert NetworkInterface("a") != NetworkInterface("b")


def test_network_interface_not_equal_class():
    assert NetworkInterface("a") != "a"


def test_network_interface_repr():
    assert "'abc'" in repr(NetworkInterface("abc"))


def test_network_interface_device_number(mock_pool):
    add_interface_response(mock_pool, "/device-number", "0")
    assert NetworkInterface(example_mac).device_number == 0


def test_network_interface_interface_id(mock_pool):
    add_interface_response(mock_pool, "/interface-id", "eni-12345")
    assert NetworkInterface(example_mac).interface_id == "eni-12345"


def test_network_interface_ipv4_associations(mock_pool):
    add_interface_response(mock_pool, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    add_interface_response(mock_pool, "/ipv4-associations/54.0.0.0", "172.30.0.0")
    add_interface_response(mock_pool, "/ipv4-associations/54.0.0.1", "172.30.0.1")
    assert NetworkInterface(example_mac).ipv4_associations == {
        "54.0.0.0": ["172.30.0.0"],
        "54.0.0.1": ["172.30.0.1"],
    }


def test_network_interface_ipv6s(mock_pool):
    add_interface_response(
        mock_pool,
        "/ipv6s",
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b\n2001:db8:abcd:ef00::f",
    )
    assert NetworkInterface(example_mac).ipv6s == [
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b",
        "2001:db8:abcd:ef00::f",
    ]


def test_network_interface_ipv6s_none(mock_pool):
    add_interface_response(mock_pool, "/ipv6s", status=404)
    assert NetworkInterface(example_mac).ipv6s == []


def test_network_interface_ipv6_prefix(mock_pool):
    add_interface_response(
        mock_pool,
        "/ipv6-prefix",
        "2001:db8:abcd:ef00:cbe5:::/80\n2001:db8:abcd:ef00:cbe6:::/80",
    )
    assert NetworkInterface(example_mac).ipv6_prefix == [
        "2001:db8:abcd:ef00:cbe5:::/80",
        "2001:db8:abcd:ef00:cbe6:::/80",
    ]


def test_network_interface_ipv6_prefix_none(mock_pool):
    add_interface_response(mock_pool, "/ipv6-prefix", status=404)
    assert NetworkInterface(example_mac).ipv6_prefix == []


def test_network_interface_owner_id(mock_pool):
    add_interface_response(mock_pool, "/owner-id", "123456789012")
    assert NetworkInterface(example_mac).owner_id == "123456789012"


def test_network_interface_private_hostname(mock_pool):
    add_interface_response(
        mock_pool, "/local-hostname", "ip-172-30-0-0.eu-west-1.compute.internal"
    )
    assert (
        NetworkInterface(example_mac).private_hostname
        == "ip-172-30-0-0.eu-west-1.compute.internal"
    )


def test_network_interface_private_ipv4s(mock_pool):
    add_interface_response(mock_pool, "/local-ipv4s", "172.30.0.0\n172.30.0.1")
    assert NetworkInterface(example_mac).private_ipv4s == ["172.30.0.0", "172.30.0.1"]


def test_network_interface_public_hostname(mock_pool):
    add_interface_response(mock_pool, "/public-hostname", "")
    assert NetworkInterface(example_mac).public_hostname == ""


def test_network_interface_public_hostname_none(mock_pool):
    add_interface_response(mock_pool, "/public-hostname", status=404)
    assert NetworkInterface(example_mac).public_hostname is None


def test_network_interface_public_ipv4s(mock_pool):
    add_interface_response(mock_pool, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    assert NetworkInterface(example_mac).public_ipv4s == ["54.0.0.0", "54.0.0.1"]


def test_network_interface_public_ipv4s_empty(mock_pool):
    add_interface_response(mock_pool, "/public-ipv4s", status=404)
    assert NetworkInterface(example_mac).public_ipv4s == []


def test_network_interface_security_groups(mock_pool):
    add_interface_response(mock_pool, "/security-groups", "foo\nbar")
    assert NetworkInterface(example_mac).security_groups == ["foo", "bar"]


def test_network_interface_security_group_ids(mock_pool):
    add_interface_response(mock_pool, "/security-group-ids", "sg-12345678\nsg-12345679")
    assert NetworkInterface(example_mac).security_group_ids == [
        "sg-12345678",
        "sg-12345679",
    ]


def test_network_interface_subnet_id(mock_pool):
    add_interface_response(mock_pool, "/subnet-id", "subnet-12345678")
    assert NetworkInterface(example_mac).subnet_id == "subnet-12345678"


def test_network_interface_subnet_ipv4_cidr_block(mock_pool):
    add_interface_response(mock_pool, "/subnet-ipv4-cidr-block", "172.30.0.0/24")
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block == "172.30.0.0/24"


def test_network_interface_subnet_ipv4_cidr_block_none(mock_pool):
    add_interface_response(mock_pool, "/subnet-ipv4-cidr-block", status=404)
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block is None


def test_network_interface_subnet_ipv6_cidr_blocks(mock_pool):
    add_interface_response(
        mock_pool, "/subnet-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/64"
    )
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/64"
    ]


def test_network_interface_subnet_ipv6_cidr_blocks_none(mock_pool):
    add_interface_response(mock_pool, "/subnet-ipv6-cidr-blocks", status=404)
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == []


def test_network_interface_vpc_id(mock_pool):
    add_interface_response(mock_pool, "/vpc-id", "vpc-12345678")
    assert NetworkInterface(example_mac).vpc_id == "vpc-12345678"


def test_network_interface_vpc_ipv4_cidr_block(mock_pool):
    add_interface_response(mock_pool, "/vpc-ipv4-cidr-block", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block == "172.30.0.0/16"


def test_network_interface_vpc_ipv4_cidr_block_none(mock_pool):
    add_interface_response(mock_pool, "/vpc-ipv4-cidr-block", status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block is None


def test_network_interface_vpc_ipv4_cidr_blocks(mock_pool):
    add_interface_response(mock_pool, "/vpc-ipv4-cidr-blocks", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == ["172.30.0.0/16"]


def test_network_interface_vpc_ipv4_cidr_blocks_none(mock_pool):
    add_interface_response(mock_pool, "/vpc-ipv4-cidr-blocks", status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == []


def test_network_interface_vpc_ipv6_cidr_blocks(mock_pool):
    add_interface_response(
        mock_pool, "/vpc-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/56"
    )
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/56"
    ]


def test_network_interface_vpc_ipv6_cidr_blocks_none(mock_pool):
    add_interface_response(mock_pool, "/vpc-ipv6-cidr-blocks", status=404)
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == []


# PublicKey tests


def add_key_response(
    mock_pool: Mock,
    index: int,
    url: str,
    text: str = "",
    status: int = 200,
    **kwargs: Any,
) -> None:
    full_url = f"http://169.254.169.254/latest/meta-data/public-keys/{index}{url}"
    mock_pool._responses[("GET", full_url)] = make_response(
        status=status, body=text.encode()
    )


def test_public_key_equal():
    assert PublicKey(0) == PublicKey(0)


def test_public_key_not_equal():
    assert PublicKey(0) != PublicKey(1)


def test_public_key_not_equal_class():
    assert PublicKey(0) != 0


def test_public_key_repr():
    assert "0" in repr(PublicKey(0))


def test_public_key_openssh_key(mock_pool):
    add_key_response(mock_pool, 0, "/openssh-key", example_public_key)
    assert PublicKey(0).openssh_key == example_public_key


def test_public_key_openssh_key_none(mock_pool):
    add_key_response(mock_pool, 0, "/openssh-key", status=404)
    assert PublicKey(0).openssh_key is None
