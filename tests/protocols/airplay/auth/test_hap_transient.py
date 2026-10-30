"""Transient pairing must not request a PIN from receivers that need none."""

import plistlib
import unittest
from unittest.mock import AsyncMock, MagicMock

from pyatv.auth import hap_tlv8
from pyatv.auth.hap_srp import SRPAuthHandler
from pyatv.protocols.airplay.auth.hap_transient import (
    TRANSIENT_PIN,
    AirPlayHapTransientPairVerifyProcedure,
)
from pyatv.support.http import HttpResponse


class TransientPairingTest(unittest.IsolatedAsyncioTestCase):
    async def test_receiver_pin_requirement_and_rtsp_requests(self):
        for flags, pin_required in [
            (0, False),
            (2052, False),
            (128, True),
            (2180, True),
        ]:
            with self.subTest(status_flags=flags):
                requests = []

                async def exchange(method, uri, **kwargs):
                    requests.append((method, uri, kwargs))
                    if uri == "/info":
                        body = plistlib.dumps(
                            {"statusFlags": flags}, fmt=plistlib.FMT_BINARY
                        )
                    elif (
                        uri == "/pair-setup"
                        and len([r for r in requests if r[1] == uri]) == 1
                    ):
                        body = hap_tlv8.write_tlv(
                            {
                                hap_tlv8.TlvValue.Salt: b"salt",
                                hap_tlv8.TlvValue.PublicKey: b"key",
                            }
                        )
                    else:
                        body = b""
                    return HttpResponse(
                        "RTSP",
                        "1.0",
                        200,
                        "OK",
                        {"CSeq": str(kwargs["headers"]["CSeq"])},
                        body,
                    )

                connection = MagicMock()
                connection.send_and_receive = AsyncMock(side_effect=exchange)
                srp = MagicMock()
                srp.step2.return_value = (b"public", b"proof")
                verifier = AirPlayHapTransientPairVerifyProcedure(connection, srp)
                self.assertTrue(await verifier.verify_credentials())
                self.assertEqual(
                    [r[1] for r in requests],
                    ["/info"]
                    + (["/pair-pin-start"] if pin_required else [])
                    + ["/pair-setup", "/pair-setup"],
                )
                self.assertTrue(all(r[2]["protocol"] == "RTSP/1.0" for r in requests))
                srp.step1.assert_called_once_with(TRANSIENT_PIN)

    def test_release_srptools_accepts_real_hap_step1(self):
        srp = SRPAuthHandler()
        srp.initialize()
        srp.step1(TRANSIENT_PIN)
