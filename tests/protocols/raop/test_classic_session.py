"""Classic RAOP must not accidentally enter an encrypted AirPlay 2 session."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from pyatv.auth.hap_pairing import NO_CREDENTIALS, TRANSIENT_CREDENTIALS
from pyatv.protocols.raop.protocols import StreamContext
from pyatv.protocols.raop.protocols.airplayv1 import AirPlayV1
from pyatv.support.rtsp import ANNOUNCE_PAYLOAD


@pytest.mark.parametrize(
    "properties,password,open_session",
    [
        ({"et": "0,1", "sf": "0x4"}, None, True),
        ({"et": "0,1", "sf": "0x84"}, None, False),
        ({"et": "0,1", "pw": "true"}, None, False),
        ({"et": "0,1"}, "secret", False),
        ({"et": "1"}, None, False),
        ({"et": "invalid"}, None, False),
    ],
)
def test_classic_authentication_is_selected_from_advertised_requirements(
    properties, password, open_session
):
    context = StreamContext()
    context.credentials = TRANSIENT_CREDENTIALS
    context.password = password
    protocol = AirPlayV1(context, Mock())
    assert protocol.requires_info(properties) is not open_session
    assert (context.credentials == NO_CREDENTIALS) is open_session


@pytest.mark.asyncio
async def test_pair_verification_and_encryption_use_the_announce_connection():
    context = StreamContext()
    context.credentials = TRANSIENT_CREDENTIALS
    rtsp = Mock()
    rtsp.announce = AsyncMock()
    rtsp.setup = AsyncMock(
        return_value=Mock(
            headers={"Transport": "control_port=1;timing_port=2;server_port=3", "Session": "1"}
        )
    )
    protocol = AirPlayV1(context, rtsp)
    with patch(
        "pyatv.protocols.raop.protocols.airplayv1.verify_connection", new_callable=AsyncMock
    ) as verify:
        await protocol.setup(1, 2)
        verify.assert_awaited_once_with(context.credentials, rtsp.connection)
    rtsp.announce.assert_awaited_once()


def test_l16_announce_does_not_include_alac_decoder_parameters():
    assert "L16/44100/2" in ANNOUNCE_PAYLOAD
    assert "fmtp" not in ANNOUNCE_PAYLOAD


def test_legacy_null_auth_retains_optional_device_info_support():
    context = StreamContext()
    context.credentials = NO_CREDENTIALS
    assert AirPlayV1(context, Mock()).requires_info({"et": "0"})
