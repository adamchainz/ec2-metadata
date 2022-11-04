from __future__ import annotations

import datetime as dt
import sys
import time
from collections.abc import Iterator
from collections.abc import Mapping
from typing import Any

import requests

if sys.version_info >= (3, 8):
    from functools import cached_property
    from typing import Literal, TypedDict

    class IamInfoDict(TypedDict):
        InstanceProfileArn: str
        InstanceProfileId: str
        LastUpdated: str

    class IamSecurityCredentialsDict(TypedDict):
        LastUpdated: str
        Type: str
        AccessKeyId: str
        SecretAccessKey: str
        Token: str
        Expiration: str

    class InstanceIdentityDocumentDict(TypedDict):
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
        accountId: str
        architecture: Literal["i386", "x86_64", "arm64"]
        availabilityZone: str
        billingProducts: list[str] | None
        # devpayProductCodes: deprecated, not including
        marketplaceProductCodes: list[str] | None
        imageId: str
        instanceId: str
        instanceType: str
        kernelId: str | None
        pendingTime: str
        privateIp: str
        ramdiskId: str | None
        region: str
        version: str

else:
    from typing import Dict

    from cached_property import cached_property

    IamInfoDict = Dict[str, Any]
    IamSecurityCredentialsDict = Dict[str, Any]
    InstanceIdentityDocumentDict = Dict[str, Any]

__all__ = ("ec2_metadata",)


# Max TTL:
TOKEN_TTL_SECONDS = 21600
TOKEN_HEADER = "X-aws-ec2-metadata-token"
TOKEN_HEADER_TTL = "X-aws-ec2-metadata-token-ttl-seconds"


class BaseLazyObject:
    def clear_all(self) -> None:
        for key in tuple(self.__dict__.keys()):
            if isinstance(getattr(self.__class__, key, None), cached_property):
                del self.__dict__[key]


class EC2Metadata(BaseLazyObject):
    def __init__(
        self,
        session: requests.Session | None = None,
    ) -> None:
        if session is None:
            session = requests.Session()
        self._session = session
        self._token_updated_at = 0.0

        # Previously we used a fixed version of the service, rather than 'latest', in
        # case any backward incompatible changes were made. It seems metadata service
        # v2 only operates with 'latest' at time of writing (2020-02-12).
        self.service_url = "http://169.254.169.254/latest/"
        self.dynamic_url = f"{self.service_url}dynamic/"
        self.metadata_url = f"{self.service_url}meta-data/"
        self.userdata_url = f"{self.service_url}user-data/"

    def _ensure_token_is_fresh(self) -> None:
        now = time.time()
        # Refresh up to 60 seconds before expiry
        if now - self._token_updated_at > (TOKEN_TTL_SECONDS - 60):
            token_response = self._session.put(
                f"{self.service_url}api/token",
                headers={TOKEN_HEADER_TTL: str(TOKEN_TTL_SECONDS)},
                timeout=5.0,
            )
            if token_response.status_code != 200:
                token_response.raise_for_status()
            token = token_response.text
            self._session.headers.update({TOKEN_HEADER: token})
            self._token_updated_at = now

    def _get_url(self, url: str, allow_404: bool = False) -> requests.Response:
        self._ensure_token_is_fresh()
        resp = self._session.get(url, timeout=1.0)
        if resp.status_code != 404 or not allow_404:
            resp.raise_for_status()
        return resp

    def clear_all(self) -> None:
        super().clear_all()
        self._session.headers.pop(TOKEN_HEADER, None)
        self._token_updated_at = 0

    @property
    def account_id(self) -> str:
        return self.instance_identity_document["accountId"]

    @cached_property
    def ami_id(self) -> str:
        return self._get_url(f"{self.metadata_url}ami-id").text

    @property
    def autoscaling_target_lifecycle_state(self) -> str | None:
        resp = self._get_url(
            f"{self.metadata_url}autoscaling/target-lifecycle-state",
            allow_404=True,
        )
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def availability_zone(self) -> str:
        return self._get_url(f"{self.metadata_url}placement/availability-zone").text

    @cached_property
    def availability_zone_id(self) -> str | None:
        resp = self._get_url(
            f"{self.metadata_url}placement/availability-zone-id", allow_404=True
        )
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def ami_launch_index(self) -> int:
        return int(self._get_url(f"{self.metadata_url}ami-launch-index").text)

    @cached_property
    def ami_manifest_path(self) -> str:
        return self._get_url(f"{self.metadata_url}ami-manifest-path").text

    @cached_property
    def iam_info(self) -> IamInfoDict | None:
        resp = self._get_url(f"{self.metadata_url}iam/info", allow_404=True)
        if resp.status_code == 404:
            return None
        result: IamInfoDict = resp.json()
        return result

    @property
    def iam_security_credentials(self) -> IamSecurityCredentialsDict | None:
        instance_profile_name = self.instance_profile_name
        if instance_profile_name is None:
            return None
        result: IamSecurityCredentialsDict = self._get_url(
            f"{self.metadata_url}iam/security-credentials/{instance_profile_name}",
        ).json()
        return result

    @property
    def instance_action(self) -> str:
        return self._get_url(f"{self.metadata_url}instance-action").text

    @cached_property
    def instance_id(self) -> str:
        return self._get_url(f"{self.metadata_url}instance-id").text

    @cached_property
    def instance_identity_document(self) -> InstanceIdentityDocumentDict:
        result: InstanceIdentityDocumentDict = self._get_url(
            f"{self.dynamic_url}instance-identity/document"
        ).json()
        return result

    @property
    def instance_profile_arn(self) -> str | None:
        iam_info = self.iam_info
        if iam_info is None:
            return None
        return iam_info["InstanceProfileArn"]

    @property
    def instance_profile_id(self) -> str | None:
        iam_info = self.iam_info
        if iam_info is None:
            return None
        return iam_info["InstanceProfileId"]

    @property
    def instance_profile_name(self) -> str | None:
        instance_profile_arn = self.instance_profile_arn
        if instance_profile_arn is None:
            return None
        return instance_profile_arn.rsplit("/", 1)[-1]

    @cached_property
    def instance_type(self) -> str:
        return self._get_url(f"{self.metadata_url}instance-type").text

    @cached_property
    def kernel_id(self) -> str | None:
        resp = self._get_url(f"{self.metadata_url}kernel-id", allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def mac(self) -> str:
        return self._get_url(f"{self.metadata_url}mac").text

    @cached_property
    def network_interfaces(self) -> dict[str, NetworkInterface]:
        macs_text = self._get_url(f"{self.metadata_url}network/interfaces/macs/").text
        macs = [line.rstrip("/") for line in macs_text.splitlines()]
        return {mac: NetworkInterface(mac, self) for mac in macs}

    @cached_property
    def private_hostname(self) -> str:
        return self._get_url(f"{self.metadata_url}local-hostname").text

    @cached_property
    def private_ipv4(self) -> str:
        return self._get_url(f"{self.metadata_url}local-ipv4").text

    @cached_property
    def public_hostname(self) -> str | None:
        resp = self._get_url(f"{self.metadata_url}public-hostname", allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def public_ipv4(self) -> str | None:
        resp = self._get_url(f"{self.metadata_url}public-ipv4", allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def partition(self) -> str:
        return self._get_url(f"{self.metadata_url}services/partition").text

    @cached_property
    def domain(self) -> str:
        return self._get_url(f"{self.metadata_url}services/domain").text

    @cached_property
    def region(self) -> str:
        return self.instance_identity_document["region"]

    @cached_property
    def reservation_id(self) -> str:
        return self._get_url(f"{self.metadata_url}reservation-id").text

    @cached_property
    def security_groups(self) -> list[str]:
        return self._get_url(f"{self.metadata_url}security-groups").text.splitlines()

    @property
    def spot_instance_action(self) -> SpotInstanceAction | None:
        resp = self._get_url(f"{self.metadata_url}spot/instance-action", allow_404=True)
        if resp.status_code == 404:
            return None
        data = resp.json()
        return SpotInstanceAction(
            data["action"],
            dt.datetime.fromisoformat(data["time"].rstrip("Z")).replace(
                tzinfo=dt.timezone.utc
            ),
        )

    @cached_property
    def tags(self) -> InstanceTags:
        resp = self._get_url(f"{self.metadata_url}tags/instance/")
        return InstanceTags(resp.text.splitlines(), self)

    @cached_property
    def user_data(self) -> bytes | None:
        resp = self._get_url(self.userdata_url, allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.content


if sys.version_info > (3, 9):
    InstanceTagsBase = Mapping[str, str]
else:
    InstanceTagsBase = Mapping


class InstanceTags(InstanceTagsBase):
    def __init__(self, names: list[str], parent: EC2Metadata) -> None:
        self._map: dict[str, str | None] = {name: None for name in names}
        self.parent = parent

    def __getitem__(self, name: str) -> str:
        value = self._map[name]
        if value is None:
            resp = self.parent._get_url(
                f"{self.parent.metadata_url}tags/instance/{name}"
            )
            value = resp.text
            self._map[name] = value
        return value

    def __iter__(self) -> Iterator[str]:
        return iter(self._map)

    def __len__(self) -> int:
        return len(self._map)


class NetworkInterface(BaseLazyObject):
    def __init__(self, mac: str, parent: EC2Metadata | None = None) -> None:
        self.mac = mac
        if parent is None:
            self.parent = ec2_metadata
        else:
            self.parent = parent

    def __repr__(self) -> str:
        return f"NetworkInterface({repr(self.mac)})"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, NetworkInterface)
            and self.mac == other.mac
            and self.parent == other.parent
        )

    def _url(self, item: str) -> str:
        return f"{self.parent.metadata_url}network/interfaces/macs/{self.mac}/{item}"

    @cached_property
    def device_number(self) -> int:
        return int(self.parent._get_url(self._url("device-number")).text)

    @cached_property
    def interface_id(self) -> str:
        return self.parent._get_url(self._url("interface-id")).text

    @cached_property
    def ipv4_associations(self) -> dict[str, list[str]]:
        associations = {}
        for public_ip in self.public_ipv4s:
            url = self._url(f"ipv4-associations/{public_ip}")
            resp = self.parent._get_url(url)
            private_ips = resp.text.splitlines()
            associations[public_ip] = private_ips
        return associations

    @cached_property
    def ipv6s(self) -> list[str]:
        resp = self.parent._get_url(self._url("ipv6s"), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def owner_id(self) -> str:
        return self.parent._get_url(self._url("owner-id")).text

    @cached_property
    def private_hostname(self) -> str:
        return self.parent._get_url(self._url("local-hostname")).text

    @cached_property
    def private_ipv4s(self) -> list[str]:
        return self.parent._get_url(self._url("local-ipv4s")).text.splitlines()

    @cached_property
    def public_hostname(self) -> str | None:
        resp = self.parent._get_url(self._url("public-hostname"), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def public_ipv4s(self) -> list[str]:
        resp = self.parent._get_url(self._url("public-ipv4s"), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def security_groups(self) -> list[str]:
        return self.parent._get_url(self._url("security-groups")).text.splitlines()

    @cached_property
    def security_group_ids(self) -> list[str]:
        return self.parent._get_url(self._url("security-group-ids")).text.splitlines()

    @cached_property
    def subnet_id(self) -> str:
        return self.parent._get_url(self._url("subnet-id")).text

    @cached_property
    def subnet_ipv4_cidr_block(self) -> str | None:
        resp = self.parent._get_url(self._url("subnet-ipv4-cidr-block"), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def subnet_ipv6_cidr_blocks(self) -> list[str]:
        resp = self.parent._get_url(
            self._url("subnet-ipv6-cidr-blocks"), allow_404=True
        )
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def vpc_id(self) -> str:
        return self.parent._get_url(self._url("vpc-id")).text

    @cached_property
    def vpc_ipv4_cidr_block(self) -> str | None:
        resp = self.parent._get_url(self._url("vpc-ipv4-cidr-block"), allow_404=True)
        if resp.status_code == 404:
            return None
        return resp.text

    @cached_property
    def vpc_ipv4_cidr_blocks(self) -> list[str]:
        resp = self.parent._get_url(self._url("vpc-ipv4-cidr-blocks"), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()

    @cached_property
    def vpc_ipv6_cidr_blocks(self) -> list[str]:
        resp = self.parent._get_url(self._url("vpc-ipv6-cidr-blocks"), allow_404=True)
        if resp.status_code == 404:
            return []
        return resp.text.splitlines()


if sys.version_info >= (3, 8):
    _ActionType = Literal["hibernate", "stop", "terminate"]
else:
    _ActionType = str


class SpotInstanceAction:
    def __init__(self, action: _ActionType, time: dt.datetime) -> None:
        self.action = action
        self.time = time


ec2_metadata = EC2Metadata()
