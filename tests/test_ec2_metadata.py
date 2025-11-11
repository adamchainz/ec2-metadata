from __future__ import annotations

import datetime as dt
import json
from typing import Any
from unittest.mock import Mock, patch

import pytest
import urllib3

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


def _mock_response(
    status: int = 200, data: str | bytes = "", json_data: dict[str, Any] | None = None
) -> Mock:
    """Create a mock urllib3 response."""
    response = Mock(spec=urllib3.BaseHTTPResponse)
    response.status = status
    if json_data is not None:
        response.data = json.dumps(json_data).encode("utf-8")
    elif isinstance(data, str):
        response.data = data.encode("utf-8")
    else:
        response.data = data
    return response


class MockRouter:
    """Routes urllib3 requests to appropriate mock responses."""

    def __init__(self):
        self.routes: dict[tuple[str, str], Mock] = {}
        self.call_count: dict[tuple[str, str], int] = {}

    def add_route(
        self,
        method: str,
        url: str,
        status: int = 200,
        data: str | bytes = "",
        json_data: dict[str, Any] | None = None,
    ) -> None:
        """Add a route for a specific method and URL."""
        key = (method, url)
        self.routes[key] = _mock_response(status, data, json_data)
        self.call_count[key] = 0

    def request(self, method: str, url: str, **kwargs: Any) -> Mock:
        """Handle a request and return the appropriate mock response."""
        key = (method, url)
        self.call_count[key] = self.call_count.get(key, 0) + 1

        if key in self.routes:
            return self.routes[key]

        # Default token response
        if method == "PUT" and url.endswith("/api/token"):
            return _mock_response(status=200, data="example-token")

        # Return 404 for unmocked requests
        return _mock_response(status=404)


@pytest.fixture
def mock_router():
    """Fixture that provides a mock router and patches urllib3.PoolManager."""
    router = MockRouter()

    with patch.object(ec2_metadata, "_session") as mock_session:
        mock_session.request.side_effect = router.request
        yield router


example_mac = "00:11:22:33:44:55"
example_public_key = "ssh-rsa AAAAblahblahblah= exampleuser@examplehost\n"

# EC2Metadata tests


def test_custom_session():
    custom_pool = urllib3.PoolManager()
    EC2Metadata(session=custom_pool)


def add_identity_doc_response(
    mock_router: MockRouter,
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
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        json_data=identity_doc,
    )
    return identity_doc


def test_account_id(mock_router):
    add_identity_doc_response(mock_router, account_id="1234")
    assert ec2_metadata.account_id == "1234"


def test_account_id_token_error(mock_router):
    mock_router.add_route("PUT", "http://169.254.169.254/latest/api/token", status=500)
    with pytest.raises(urllib3.exceptions.HTTPError):
        ec2_metadata.account_id  # noqa: B018


def test_account_id_error(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        status=500,
    )
    with pytest.raises(urllib3.exceptions.HTTPError):
        ec2_metadata.account_id  # noqa: B018


def test_ami_id(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-id", data="ami-12345678"
    )
    assert ec2_metadata.ami_id == "ami-12345678"


def test_ami_id_cached(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-id", data="ami-12345678"
    )
    ec2_metadata.ami_id  # noqa: B018
    # Should only be called once due to caching
    assert mock_router.call_count[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] == 1
    ec2_metadata.ami_id  # noqa: B018  - no additional call
    assert mock_router.call_count[("GET", "http://169.254.169.254/latest/meta-data/ami-id")] == 1


def test_ami_id_cached_cleared(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-id", data="ami-12345678"
    )
    ec2_metadata.ami_id  # noqa: B018
    ec2_metadata.clear_all()

    # After clear, should raise error
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-id", status=500
    )
    with pytest.raises(urllib3.exceptions.HTTPError):
        ec2_metadata.ami_id  # noqa: B018


def test_ami_launch_index(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-launch-index", data="0"
    )
    assert ec2_metadata.ami_launch_index == 0


def test_ami_manifest_path(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/ami-manifest-path", data="(unknown)"
    )
    assert ec2_metadata.ami_manifest_path == "(unknown)"


def test_autoscaling_target_lifecycle_state_none(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/autoscaling/target-lifecycle-state",
        status=404,
    )
    assert ec2_metadata.autoscaling_target_lifecycle_state is None


def test_autoscaling_target_lifecycle_state_in_service(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/autoscaling/target-lifecycle-state",
        data="InService",
    )
    assert ec2_metadata.autoscaling_target_lifecycle_state == "InService"


def test_availability_zone(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        data="eu-west-1a",
    )
    assert ec2_metadata.availability_zone == "eu-west-1a"


def test_availability_zone_id(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone-id",
        data="use1-az6",
    )
    assert ec2_metadata.availability_zone_id == "use1-az6"


def test_availability_zone_id_none(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/placement/availability-zone-id",
        status=404,
    )
    assert ec2_metadata.availability_zone_id is None


def test_domain(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/services/domain",
        data="amazonaws.com",
    )
    assert ec2_metadata.domain == "amazonaws.com"


def test_iam_info(mock_router):
    result = {
        "InstanceProfileArn": "arn:foobar/myInstanceProfile",
        "InstanceProfileId": "some-id",
        "LastUpdated": "2022-08-12T10:22:29Z",
    }
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/iam/info", json_data=result
    )
    assert ec2_metadata.iam_info == result


def test_iam_info_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/iam/info", status=404
    )
    assert ec2_metadata.iam_info is None


def test_iam_info_unexpected(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/iam/info", status=500
    )
    with pytest.raises(urllib3.exceptions.HTTPError):
        ec2_metadata.iam_info  # noqa: B018


def test_iam_security_credentials(mock_router):
    profile = "myInstanceProfile"
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/iam/info",
        json_data={"InstanceProfileArn": f"arn:foobar/{profile}"},
    )
    result = {
        "LastUpdated": "2022-08-12T10:48:52Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "some-access-key-id",
        "SecretAccessKey": "some-secret-access-key",
        "Token": "some-token",
        "Expiration": "2022-08-12T17:03:05Z",
    }
    mock_router.add_route(
        "GET",
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile}",
        json_data=result,
    )
    assert ec2_metadata.iam_security_credentials == result


def test_iam_security_credentials_none(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/iam/info",
        status=404,
    )
    assert ec2_metadata.iam_security_credentials is None


def test_instance_action(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/instance-action", data="none"
    )
    assert ec2_metadata.instance_action == "none"


def test_instance_id(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/instance-id", data="i-12345678"
    )
    assert ec2_metadata.instance_id == "i-12345678"


def test_instance_identity(mock_router):
    identity_doc = add_identity_doc_response(mock_router)
    assert ec2_metadata.instance_identity_document == identity_doc


def test_instance_life_cycle(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/instance-life-cycle", data="on-demand"
    )
    assert ec2_metadata.instance_life_cycle == "on-demand"


def test_instance_profile_arn(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/iam/info",
        data='{"InstanceProfileArn": "arn:foobar/myInstanceProfile"}',
    )
    assert ec2_metadata.instance_profile_arn == "arn:foobar/myInstanceProfile"


def test_instance_profile_arn_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/iam/info", status=404
    )
    assert ec2_metadata.instance_profile_arn is None


def test_instance_profile_id(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/iam/info",
        data='{"InstanceProfileId": "some-id"}',
    )
    assert ec2_metadata.instance_profile_id == "some-id"


def test_instance_profile_id_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/iam/info", status=404
    )
    assert ec2_metadata.instance_profile_id is None


def test_instance_profile_name(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/iam/info",
        data='{"InstanceProfileArn": "arn:foobar/myInstanceProfile"}',
    )
    assert ec2_metadata.instance_profile_name == "myInstanceProfile"


def test_instance_type(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/instance-type", data="t2.nano"
    )
    assert ec2_metadata.instance_type == "t2.nano"


def test_kernel_id(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/kernel-id", data="aki-dc9ed9af"
    )
    assert ec2_metadata.kernel_id == "aki-dc9ed9af"


def test_kernel_id_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/kernel-id", status=404
    )
    assert ec2_metadata.kernel_id is None


def test_mac(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/mac", data=example_mac
    )
    assert ec2_metadata.mac == example_mac


def test_network_interfaces(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
        data=f"{example_mac}/",
    )
    assert ec2_metadata.network_interfaces == {
        example_mac: NetworkInterface(example_mac, ec2_metadata)
    }


def test_partition(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/services/partition",
        data="aws",
    )
    assert ec2_metadata.partition == "aws"


def test_private_hostname(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/local-hostname",
        data="ip-172-30-0-0.eu-west-1.compute.internal",
    )
    assert ec2_metadata.private_hostname == "ip-172-30-0-0.eu-west-1.compute.internal"


def test_private_ipv4(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/local-ipv4", data="172.30.0.0"
    )
    assert ec2_metadata.private_ipv4 == "172.30.0.0"


def test_public_hostname(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/public-hostname",
        data="ec2-1-2-3-4.compute-1.amazonaws.com",
    )
    assert ec2_metadata.public_hostname == "ec2-1-2-3-4.compute-1.amazonaws.com"


def test_public_hostname_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/public-hostname", status=404
    )
    assert ec2_metadata.public_hostname is None


def test_public_ipv4(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/public-ipv4", data="1.2.3.4"
    )
    assert ec2_metadata.public_ipv4 == "1.2.3.4"


def test_public_ipv4_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/public-ipv4", status=404
    )
    assert ec2_metadata.public_ipv4 is None


def test_public_keys(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/public-keys/", data="0=somekey"
    )
    assert ec2_metadata.public_keys == {"somekey": PublicKey(0, ec2_metadata)}


def test_public_keys_none(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/public-keys/", status=404
    )
    assert ec2_metadata.public_keys == {}


def test_region(mock_router):
    add_identity_doc_response(mock_router, region="eu-whatever-1")
    assert ec2_metadata.region == "eu-whatever-1"


def test_reservation_id(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/reservation-id",
        data="r-12345678901234567",
    )
    assert ec2_metadata.reservation_id == "r-12345678901234567"


def test_security_groups_single(mock_router):
    # most common case: a single SG
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/security-groups",
        data="security-group-one",
    )
    assert ec2_metadata.security_groups == ["security-group-one"]


def test_security_groups_two(mock_router):
    # another common case: multiple SGs
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/security-groups",
        data="security-group-one\nsecurity-group-2",
    )
    assert ec2_metadata.security_groups == ["security-group-one", "security-group-2"]


def test_security_groups_emptystring(mock_router):
    # Check '' too. Can't create an instance without a SG on EC2 but we should
    # safely handle it, perhaps it's possible in e.g. OpenStack.
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/security-groups", data=""
    )
    assert ec2_metadata.security_groups == []


def test_spot_instance_action_none(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/spot/instance-action",
        status=404,
    )
    assert ec2_metadata.spot_instance_action is None


def test_spot_instance_action(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/spot/instance-action",
        data='{"action": "stop", "time": "2017-09-18T08:22:00Z"}',
    )
    sia = ec2_metadata.spot_instance_action
    assert sia is not None
    assert sia.action == "stop"
    assert sia.time == dt.datetime(2017, 9, 18, 8, 22, 0, tzinfo=dt.timezone.utc)


def test_tags_not_enabled(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/tags/instance/", status=404
    )
    with pytest.raises(urllib3.exceptions.HTTPError):
        ec2_metadata.tags  # noqa: B018


def test_tags_empty(mock_router):
    mock_router.add_route(
        "GET", "http://169.254.169.254/latest/meta-data/tags/instance/", data=""
    )
    assert dict(ec2_metadata.tags) == {}


def test_tags_one(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/",
        data="Name",
    )
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/Name",
        data="test-instance",
    )

    assert dict(ec2_metadata.tags) == {"Name": "test-instance"}


def test_tags_multiple(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/",
        data="Name\ncustom-tag",
    )
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/Name",
        data="test-instance",
    )
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/custom-tag",
        data="custom-value",
    )

    assert dict(ec2_metadata.tags) == {
        "Name": "test-instance",
        "custom-tag": "custom-value",
    }


def test_tags_repeat_access(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/",
        data="Name",
    )
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/Name",
        data="test-instance",
    )

    ec2_metadata.tags["Name"]
    ec2_metadata.tags["Name"]

    # Should only be called once per endpoint due to caching in InstanceTags
    assert mock_router.call_count[("GET", "http://169.254.169.254/latest/meta-data/tags/instance/Name")] == 1


def test_tags_iter(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/",
        data="Name",
    )

    assert list(iter(ec2_metadata.tags)) == ["Name"]


def test_tags_len(mock_router):
    mock_router.add_route(
        "GET",
        "http://169.254.169.254/latest/meta-data/tags/instance/",
        data="Name\ncustom-tag",
    )

    assert len(ec2_metadata.tags) == 2


def test_user_data_none(mock_router):
    mock_router.add_route("GET", "http://169.254.169.254/latest/user-data/", status=404)
    assert ec2_metadata.user_data is None


def test_user_data_something(mock_router):
    mock_router.add_route("GET", "http://169.254.169.254/latest/user-data/", data=b"foobar")
    assert ec2_metadata.user_data == b"foobar"


# NetworkInterface tests


def add_interface_response(
    mock_router: MockRouter, url: str, data: str | bytes = "", status: int = 200
) -> None:
    mock_router.add_route(
        "GET",
        f"http://169.254.169.254/latest/meta-data/network/interfaces/macs/{example_mac}{url}",
        data=data,
        status=status,
    )


def test_network_interface_equal():
    assert NetworkInterface("a") == NetworkInterface("a")


def test_network_interface_not_equal():
    assert NetworkInterface("a") != NetworkInterface("b")


def test_network_interface_not_equal_class():
    assert NetworkInterface("a") != "a"


def test_network_interface_repr():
    assert "'abc'" in repr(NetworkInterface("abc"))


def test_network_interface_device_number(mock_router):
    add_interface_response(mock_router, "/device-number", "0")
    assert NetworkInterface(example_mac).device_number == 0


def test_network_interface_interface_id(mock_router):
    add_interface_response(mock_router, "/interface-id", "eni-12345")
    assert NetworkInterface(example_mac).interface_id == "eni-12345"


def test_network_interface_ipv4_associations(mock_router):
    add_interface_response(mock_router, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    add_interface_response(
        mock_router, "/ipv4-associations/54.0.0.0", "172.30.0.0"
    )
    add_interface_response(
        mock_router, "/ipv4-associations/54.0.0.1", "172.30.0.1"
    )
    assert NetworkInterface(example_mac).ipv4_associations == {
        "54.0.0.0": ["172.30.0.0"],
        "54.0.0.1": ["172.30.0.1"],
    }


def test_network_interface_ipv6s(mock_router):
    add_interface_response(
        mock_router,
        "/ipv6s",
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b\n2001:db8:abcd:ef00::f",
    )
    assert NetworkInterface(example_mac).ipv6s == [
        "2001:db8:abcd:ef00:cbe5:798:aa26:169b",
        "2001:db8:abcd:ef00::f",
    ]


def test_network_interface_ipv6s_none(mock_router):
    add_interface_response(mock_router, "/ipv6s", status=404)
    assert NetworkInterface(example_mac).ipv6s == []


def test_network_interface_ipv6_prefix(mock_router):
    add_interface_response(
        mock_router,
        "/ipv6-prefix",
        "2001:db8:abcd:ef00:cbe5:::/80\n2001:db8:abcd:ef00:cbe6:::/80",
    )
    assert NetworkInterface(example_mac).ipv6_prefix == [
        "2001:db8:abcd:ef00:cbe5:::/80",
        "2001:db8:abcd:ef00:cbe6:::/80",
    ]


def test_network_interface_ipv6_prefix_none(mock_router):
    add_interface_response(mock_router, "/ipv6-prefix", status=404)
    assert NetworkInterface(example_mac).ipv6_prefix == []


def test_network_interface_owner_id(mock_router):
    add_interface_response(mock_router, "/owner-id", "123456789012")
    assert NetworkInterface(example_mac).owner_id == "123456789012"


def test_network_interface_private_hostname(mock_router):
    add_interface_response(
        mock_router, "/local-hostname", "ip-172-30-0-0.eu-west-1.compute.internal"
    )
    assert (
        NetworkInterface(example_mac).private_hostname
        == "ip-172-30-0-0.eu-west-1.compute.internal"
    )


def test_network_interface_private_ipv4s(mock_router):
    add_interface_response(mock_router, "/local-ipv4s", "172.30.0.0\n172.30.0.1")
    assert NetworkInterface(example_mac).private_ipv4s == ["172.30.0.0", "172.30.0.1"]


def test_network_interface_public_hostname(mock_router):
    add_interface_response(mock_router, "/public-hostname", "")
    assert NetworkInterface(example_mac).public_hostname == ""


def test_network_interface_public_hostname_none(mock_router):
    add_interface_response(mock_router, "/public-hostname", status=404)
    assert NetworkInterface(example_mac).public_hostname is None


def test_network_interface_public_ipv4s(mock_router):
    add_interface_response(mock_router, "/public-ipv4s", "54.0.0.0\n54.0.0.1")
    assert NetworkInterface(example_mac).public_ipv4s == ["54.0.0.0", "54.0.0.1"]


def test_network_interface_public_ipv4s_empty(mock_router):
    add_interface_response(mock_router, "/public-ipv4s", status=404)
    assert NetworkInterface(example_mac).public_ipv4s == []


def test_network_interface_security_groups(mock_router):
    add_interface_response(mock_router, "/security-groups", "foo\nbar")
    assert NetworkInterface(example_mac).security_groups == ["foo", "bar"]


def test_network_interface_security_group_ids(mock_router):
    add_interface_response(
        mock_router, "/security-group-ids", "sg-12345678\nsg-12345679"
    )
    assert NetworkInterface(example_mac).security_group_ids == [
        "sg-12345678",
        "sg-12345679",
    ]


def test_network_interface_subnet_id(mock_router):
    add_interface_response(mock_router, "/subnet-id", "subnet-12345678")
    assert NetworkInterface(example_mac).subnet_id == "subnet-12345678"


def test_network_interface_subnet_ipv4_cidr_block(mock_router):
    add_interface_response(mock_router, "/subnet-ipv4-cidr-block", "172.30.0.0/24")
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block == "172.30.0.0/24"


def test_network_interface_subnet_ipv4_cidr_block_none(mock_router):
    add_interface_response(mock_router, "/subnet-ipv4-cidr-block", status=404)
    assert NetworkInterface(example_mac).subnet_ipv4_cidr_block is None


def test_network_interface_subnet_ipv6_cidr_blocks(mock_router):
    add_interface_response(
        mock_router, "/subnet-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/64"
    )
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/64"
    ]


def test_network_interface_subnet_ipv6_cidr_blocks_none(mock_router):
    add_interface_response(
        mock_router, "/subnet-ipv6-cidr-blocks", status=404
    )
    assert NetworkInterface(example_mac).subnet_ipv6_cidr_blocks == []


def test_network_interface_vpc_id(mock_router):
    add_interface_response(mock_router, "/vpc-id", "vpc-12345678")
    assert NetworkInterface(example_mac).vpc_id == "vpc-12345678"


def test_network_interface_vpc_ipv4_cidr_block(mock_router):
    add_interface_response(mock_router, "/vpc-ipv4-cidr-block", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block == "172.30.0.0/16"


def test_network_interface_vpc_ipv4_cidr_block_none(mock_router):
    add_interface_response(mock_router, "/vpc-ipv4-cidr-block", status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_block is None


def test_network_interface_vpc_ipv4_cidr_blocks(mock_router):
    add_interface_response(mock_router, "/vpc-ipv4-cidr-blocks", "172.30.0.0/16")
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == ["172.30.0.0/16"]


def test_network_interface_vpc_ipv4_cidr_blocks_none(mock_router):
    add_interface_response(mock_router, "/vpc-ipv4-cidr-blocks", status=404)
    assert NetworkInterface(example_mac).vpc_ipv4_cidr_blocks == []


def test_network_interface_vpc_ipv6_cidr_blocks(mock_router):
    add_interface_response(
        mock_router, "/vpc-ipv6-cidr-blocks", "2001:db8:abcd:ef00::/56"
    )
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == [
        "2001:db8:abcd:ef00::/56"
    ]


def test_network_interface_vpc_ipv6_cidr_blocks_none(mock_router):
    add_interface_response(mock_router, "/vpc-ipv6-cidr-blocks", status=404)
    assert NetworkInterface(example_mac).vpc_ipv6_cidr_blocks == []


# PublicKey tests


def add_key_response(
    mock_router: MockRouter,
    index: int,
    url: str,
    data: str = "",
    status: int = 200,
) -> None:
    mock_router.add_route(
        "GET",
        f"http://169.254.169.254/latest/meta-data/public-keys/{index}{url}",
        data=data,
        status=status,
    )


def test_public_key_equal():
    assert PublicKey(0) == PublicKey(0)


def test_public_key_not_equal():
    assert PublicKey(0) != PublicKey(1)


def test_public_key_not_equal_class():
    assert PublicKey(0) != 0


def test_public_key_repr():
    assert "0" in repr(PublicKey(0))


def test_public_key_openssh_key(mock_router):
    add_key_response(mock_router, 0, "/openssh-key", example_public_key)
    assert PublicKey(0).openssh_key == example_public_key


def test_public_key_openssh_key_none(mock_router):
    add_key_response(mock_router, 0, "/openssh-key", status=404)
    assert PublicKey(0).openssh_key is None
