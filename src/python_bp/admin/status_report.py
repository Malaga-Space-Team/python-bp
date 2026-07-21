# Copyright (c) 2026 Malaga Space Team
"""Bundle status reports as specified by RFC 9171, Section 6.1.1.

This module models the CBOR data items used by a Bundle Protocol Version 7
status report.  It deliberately exposes CBOR-compatible Python structures
rather than encoded bytes; byte serialization belongs in ``codec.cbor``.
"""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar, Self, TypeAlias


CBORArray: TypeAlias = list[object]
EndpointID: TypeAlias = tuple[int, object]
CreationTimestamp: TypeAlias = tuple[int, int]


class StatusReportError(ValueError):
    """Raised when a status report does not conform to RFC 9171."""


class StatusFlag(IntEnum):
    """Positions of the four status assertions mandated by RFC 9171."""

    RECEIVED = 0
    FORWARDED = 1
    DELIVERED = 2
    DELETED = 3


class ReasonCode(IntEnum):
    """Status report reason codes initially registered for BPv7."""

    NO_ADDITIONAL_INFORMATION = 0
    LIFETIME_EXPIRED = 1
    FORWARDED_OVER_UNIDIRECTIONAL_LINK = 2
    TRANSMISSION_CANCELED = 3
    DEPLETED_STORAGE = 4
    DESTINATION_ENDPOINT_ID_UNAVAILABLE = 5
    NO_KNOWN_ROUTE_TO_DESTINATION = 6
    NO_TIMELY_CONTACT_WITH_NEXT_NODE = 7
    BLOCK_UNINTELLIGIBLE = 8
    HOP_LIMIT_EXCEEDED = 9
    TRAFFIC_PARED = 10
    BLOCK_UNSUPPORTED = 11


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _require_uint(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatusReportError(f"{name} must be a CBOR unsigned integer")
    return int(value)


def _normalise_endpoint_id(value: object) -> EndpointID:
    if not _is_sequence(value) or len(value) != 2:
        raise StatusReportError("source_node_eid must be a two-item EID array")

    scheme = _require_uint("source_node_eid URI scheme code", value[0])
    service_specific_part = value[1]

    if scheme == 1:
        is_null_endpoint = (
            isinstance(service_specific_part, int)
            and not isinstance(service_specific_part, bool)
            and service_specific_part == 0
        )
        if not isinstance(service_specific_part, str) and not is_null_endpoint:
            raise StatusReportError(
                "a dtn-scheme EID service-specific part must be text or zero"
            )
    elif scheme == 2:
        if not _is_sequence(service_specific_part) or len(service_specific_part) != 2:
            raise StatusReportError(
                "an ipn-scheme EID service-specific part must be a two-item array"
            )
        service_specific_part = (
            _require_uint("IPN node number", service_specific_part[0]),
            _require_uint("IPN service number", service_specific_part[1]),
        )
    else:
        # Other registered URI schemes are permitted by BPv7 extensions.
        service_specific_part = deepcopy(service_specific_part)

    return scheme, service_specific_part


def _endpoint_id_to_cbor(value: EndpointID) -> CBORArray:
    scheme, service_specific_part = value
    if scheme == 2:
        service_specific_part = list(service_specific_part)
    else:
        service_specific_part = deepcopy(service_specific_part)
    return [scheme, service_specific_part]


def _normalise_creation_timestamp(value: object) -> CreationTimestamp:
    if not _is_sequence(value) or len(value) != 2:
        raise StatusReportError(
            "subject_creation_timestamp must be a two-item array"
        )
    return (
        _require_uint("subject creation DTN time", value[0]),
        _require_uint("subject creation sequence number", value[1]),
    )


@dataclass(frozen=True, slots=True)
class StatusItem:
    """One status assertion and its optional DTN timestamp.

    A timestamp is legal only for an asserted status.  Whether an asserted
    status must include it depends on the subject bundle's ``Report status
    time`` processing flag and can be checked with
    :meth:`StatusReport.validate_status_times`.
    """

    asserted: bool
    timestamp: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.asserted, bool):
            raise StatusReportError("status indicator must be a CBOR Boolean")
        if self.timestamp is not None:
            _require_uint("status timestamp", self.timestamp)
            if not self.asserted:
                raise StatusReportError(
                    "an unasserted status item cannot contain a timestamp"
                )

    def to_cbor_structure(self) -> CBORArray:
        """Return the one- or two-item CBOR-compatible status array."""

        result: CBORArray = [self.asserted]
        if self.timestamp is not None:
            result.append(self.timestamp)
        return result

    @classmethod
    def from_cbor_structure(cls, value: object) -> Self:
        """Parse and validate one status information item."""

        if not _is_sequence(value) or len(value) not in (1, 2):
            raise StatusReportError("a status item must contain one or two items")
        asserted = value[0]
        timestamp = value[1] if len(value) == 2 else None
        return cls(asserted=asserted, timestamp=timestamp)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class BundleStatusInformation:
    """The ordered status information array from a bundle status report."""

    received: StatusItem = field(default_factory=lambda: StatusItem(False))
    forwarded: StatusItem = field(default_factory=lambda: StatusItem(False))
    delivered: StatusItem = field(default_factory=lambda: StatusItem(False))
    deleted: StatusItem = field(default_factory=lambda: StatusItem(False))
    additional: tuple[StatusItem, ...] = ()

    def __post_init__(self) -> None:
        for item in self.items:
            if not isinstance(item, StatusItem):
                raise StatusReportError(
                    "bundle status information must contain StatusItem values"
                )

    @property
    def items(self) -> tuple[StatusItem, ...]:
        """Return all status items in their serialized order."""

        return (
            self.received,
            self.forwarded,
            self.delivered,
            self.deleted,
            *self.additional,
        )

    def __getitem__(self, status: StatusFlag) -> StatusItem:
        return self.items[int(status)]

    def to_cbor_structure(self) -> CBORArray:
        """Return the ordered status items as CBOR-compatible arrays."""

        return [item.to_cbor_structure() for item in self.items]

    @classmethod
    def from_cbor_structure(cls, value: object) -> Self:
        """Parse the four mandatory items and any extension status items."""

        if not _is_sequence(value) or len(value) < 4:
            raise StatusReportError(
                "bundle status information must contain at least four items"
            )
        items = tuple(StatusItem.from_cbor_structure(item) for item in value)
        return cls(
            received=items[0],
            forwarded=items[1],
            delivered=items[2],
            deleted=items[3],
            additional=items[4:],
        )


@dataclass(frozen=True, slots=True)
class StatusReport:
    """A complete BPv7 bundle status report administrative record.

    ``reason_code`` accepts any unsigned integer so that reports using reason
    codes registered by supplementary specifications remain decodable.  The
    values initially registered by RFC 9171 are available through
    :class:`ReasonCode`.
    """

    RECORD_TYPE_CODE: ClassVar[int] = 1

    status_information: BundleStatusInformation
    reason_code: int
    source_node_eid: EndpointID
    subject_creation_timestamp: CreationTimestamp
    fragment_offset: int | None = None
    fragment_length: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status_information, BundleStatusInformation):
            raise StatusReportError(
                "status_information must be a BundleStatusInformation value"
            )

        object.__setattr__(
            self, "reason_code", _require_uint("reason_code", self.reason_code)
        )
        object.__setattr__(
            self,
            "source_node_eid",
            _normalise_endpoint_id(self.source_node_eid),
        )
        object.__setattr__(
            self,
            "subject_creation_timestamp",
            _normalise_creation_timestamp(self.subject_creation_timestamp),
        )

        has_offset = self.fragment_offset is not None
        has_length = self.fragment_length is not None
        if has_offset != has_length:
            raise StatusReportError(
                "fragment_offset and fragment_length must be present together"
            )
        if self.fragment_offset is not None:
            _require_uint("fragment_offset", self.fragment_offset)
            _require_uint("fragment_length", self.fragment_length)

    @property
    def is_fragment(self) -> bool:
        """Whether this report refers to a fragmentary bundle."""

        return self.fragment_offset is not None

    def validate_status_times(self, report_status_time_requested: bool) -> None:
        """Validate timestamps against the subject bundle's status-time flag.

        RFC 9171 requires a two-item status array exactly when that status is
        asserted and the subject bundle requested status times.
        """

        if not isinstance(report_status_time_requested, bool):
            raise TypeError("report_status_time_requested must be a bool")

        for item in self.status_information.items:
            timestamp_required = item.asserted and report_status_time_requested
            if (item.timestamp is not None) != timestamp_required:
                requirement = "include" if timestamp_required else "omit"
                raise StatusReportError(
                    f"status item must {requirement} its timestamp for the "
                    "subject bundle's status-time flag"
                )

    def to_record_content(self) -> CBORArray:
        """Return the four- or six-item status report content array."""

        result: CBORArray = [
            self.status_information.to_cbor_structure(),
            self.reason_code,
            _endpoint_id_to_cbor(self.source_node_eid),
            list(self.subject_creation_timestamp),
        ]
        if self.is_fragment:
            result.extend((self.fragment_offset, self.fragment_length))
        return result

    def to_admin_record(self) -> CBORArray:
        """Return the complete ``[record type, record content]`` array."""

        return [self.RECORD_TYPE_CODE, self.to_record_content()]

    @classmethod
    def from_record_content(cls, value: object) -> Self:
        """Parse a four- or six-item bundle status report content array."""

        if not _is_sequence(value) or len(value) not in (4, 6):
            raise StatusReportError(
                "status report content must contain four or six items"
            )

        fragment_offset = value[4] if len(value) == 6 else None
        fragment_length = value[5] if len(value) == 6 else None
        return cls(
            status_information=BundleStatusInformation.from_cbor_structure(value[0]),
            reason_code=value[1],  # type: ignore[arg-type]
            source_node_eid=value[2],  # type: ignore[arg-type]
            subject_creation_timestamp=value[3],  # type: ignore[arg-type]
            fragment_offset=fragment_offset,  # type: ignore[arg-type]
            fragment_length=fragment_length,  # type: ignore[arg-type]
        )

    @classmethod
    def from_admin_record(cls, value: object) -> Self:
        """Parse a complete BP administrative record of type 1."""

        if not _is_sequence(value) or len(value) != 2:
            raise StatusReportError(
                "an administrative record must contain exactly two items"
            )
        if value[0] != cls.RECORD_TYPE_CODE:
            raise StatusReportError(
                f"expected administrative record type {cls.RECORD_TYPE_CODE}"
            )
        return cls.from_record_content(value[1])


__all__ = [
    "BundleStatusInformation",
    "CreationTimestamp",
    "EndpointID",
    "ReasonCode",
    "StatusFlag",
    "StatusItem",
    "StatusReport",
    "StatusReportError",
]
