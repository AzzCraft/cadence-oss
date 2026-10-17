"""Fail-closed compatibility adapter for Cadence's future microVM backend.

There is deliberately no generic way to turn a hypervisor binary invocation
into guest execution.  A valid backend must boot an immutable guest, deliver a
bound command, collect a guest-generated signed receipt, and let cadence-core
verify that receipt against the profile's immutable trust policy.  Until that
complete protocol and a reviewed runtime image exist, this adapter must return
an explicit blocked result rather than launch a hypervisor and mislabel host
``/proc`` observations as guest isolation proof.
"""
from __future__ import annotations

from typing import Any

from .adapter import AdapterRequest, AdapterResponse, RuntimeAdapter


_REQUIRED_GUEST_RECEIPT_FIELDS = (
    "schemaVersion",
    "receiptType",
    "guestCommandSha256",
    "guestEnvironmentSha256",
    "guestFilesystemSha256",
    "guestOutputSha256",
    "kernelImageSha256",
    "rootfsSha256",
    "hypervisor",
    "hypervisorVersion",
    "observedChecks",
    "namespaceProofs",
    "signatureAlgorithm",
    "signatureKeyId",
    "signedPayloadSha256",
    "signature",
)


class MicrovmAdapter(RuntimeAdapter):
    """Keep the unsupported microVM profile explicitly unavailable.

    The historical adapter built a command line for Firecracker/QEMU/etc., but
    did not configure a bootable guest or cause ``request.command`` to execute
    inside it.  It then measured the adapter host.  Returning a blocked
    response is the only truthful behavior until a receipt-verifying guest
    transport is implemented and exercised on a real microVM builder.
    """

    def backend_type(self) -> str:
        return "microvm-runtime"

    def execute(self, request: AdapterRequest) -> AdapterResponse:
        evidence: dict[str, Any] = {
            "adapterType": "microvm",
            "isolationBackend": "microvm-runtime",
            "guestExecution": False,
            "guestReceiptVerified": False,
            "releaseEvidenceEligible": False,
            "attestationStatus": "blocked-guest-receipt-required",
            "requiredGuestReceiptFields": list(_REQUIRED_GUEST_RECEIPT_FIELDS),
            "blockedReason": (
                "microVM execution is disabled until a reviewed guest transport "
                "boots an immutable rootfs, executes the bound command in the "
                "guest, and returns a trusted signed guest receipt"
            ),
        }
        return AdapterResponse(
            exitCode=1,
            stderr=evidence["blockedReason"],
            backendEvidence=evidence,
            failureReasons=["microvm-runtime blocked: trusted guest execution and receipt verification are not implemented"],
        )


def main() -> None:
    MicrovmAdapter().run()


if __name__ == "__main__":
    main()
