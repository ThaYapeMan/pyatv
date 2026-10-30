"""Implementation of AirPlay v1 protocol logic."""

import asyncio
import logging
import plistlib
from typing import List, Mapping, Optional, Tuple
from uuid import uuid4

from pyatv import exceptions
from pyatv.auth.hap_pairing import AuthenticationType, NO_CREDENTIALS
from pyatv.protocols.airplay.auth import verify_connection
from pyatv.protocols.raop.protocols import StreamContext, StreamProtocol
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

KEEP_ALIVE_INTERVAL = 25  # Seconds

HEADERS = {
    "User-Agent": "MediaControl/1.0",
    "Content-Type": "application/x-apple-binary-plist",
}


def parse_transport(transport: str) -> Tuple[List[str], Mapping[str, str]]:
    """Parse Transport header in SETUP response."""
    params = []
    options = {}
    for option in transport.split(";"):
        if "=" in option:
            key, value = option.split("=", maxsplit=1)
            options[key] = value
        else:
            params.append(option)
    return params, options


class AirPlayV1(StreamProtocol):
    """Stream protocol used for AirPlay v1 support."""

    def __init__(self, context: StreamContext, rtsp: RtspSession) -> None:
        """Initialize a new AirPlayV1 instance."""
        super().__init__()
        self.context = context
        self.rtsp = rtsp
        self._keep_alive_task: Optional[asyncio.Future] = None

    def requires_info(self, properties: Mapping[str, str]) -> bool:
        """Open classic RAOP does not negotiate an AirPlay 2 control channel."""
        try:
            encryption = {int(value) for value in properties.get("et", "").split(",")}
            flags = int(properties.get("sf", "0"), 16)
        except ValueError:
            return True
        if (
            0 in encryption
            and not flags & (1 << 7)
            and properties.get("pw", "false").lower() != "true"
            and not self.context.password
            and self.context.credentials.type == AuthenticationType.Transient
        ):
            self.context.credentials = NO_CREDENTIALS
            _LOGGER.debug("Open classic RAOP: no /info or transient pairing")
            return False
        return True

    async def setup(self, timing_server_port: int, control_client_port: int) -> None:
        """To setup connection prior to starting to stream."""
        await verify_connection(self.context.credentials, self.rtsp.connection)

        await self.rtsp.announce(
            self.context.bytes_per_channel,
            self.context.channels,
            self.context.sample_rate,
            self.context.password,
        )

        resp = await self.rtsp.setup(
            headers={
                "Transport": (
                    "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;"
                    f"control_port={control_client_port};"
                    f"timing_port={timing_server_port}"
                )
            }
        )
        _, options = parse_transport(resp.headers["Transport"])
        self.context.timing_port = int(options.get("timing_port", 0))
        self.context.control_port = int(options["control_port"])
        self.context.rtsp_session = int(resp.headers["Session"])
        self.context.server_port = int(options["server_port"])

        _LOGGER.debug(
            "Remote ports: control=%d, timing=%d, server=%d",
            self.context.control_port,
            self.context.timing_port,
            self.context.server_port,
        )

    def teardown(self) -> None:
        """Teardown resources allocated by setup efter streaming finished."""
        if self._keep_alive_task:
            self._keep_alive_task.cancel()
            self._keep_alive_task = None

    async def start_feedback(self) -> None:
        """Start to send feedback (if supported and required)."""
        feedback = await self.rtsp.feedback(allow_error=True)
        if feedback.code == 200:
            self._keep_alive_task = asyncio.ensure_future(self._send_keep_alive())
        else:
            _LOGGER.debug("Keep-alive not supported, not starting task")

    async def _send_keep_alive(self) -> None:
        _LOGGER.debug("Starting keep-alive task")

        while True:
            try:
                await asyncio.sleep(KEEP_ALIVE_INTERVAL)

                _LOGGER.debug("Sending keep-alive feedback")
                await self.rtsp.feedback()
            except asyncio.CancelledError:
                break
            except exceptions.ProtocolError:
                _LOGGER.exception("feedback failed")

        _LOGGER.debug("Feedback task finished")

    async def send_audio_packet(
        self, transport: asyncio.DatagramTransport, rtp_header: bytes, audio: bytes
    ) -> Tuple[int, bytes]:
        """Send audio packet to receiver."""
        packet = rtp_header + audio
        transport.sendto(packet)
        return self.context.rtpseq, packet

    async def play_url(self, timing_server_port: int, url: str, position: float = 0.0):
        """Play media from a URL."""
        await verify_connection(self.context.credentials, self.rtsp.connection)

        body = {
            "Content-Location": url,
            "Start-Position": position,
            "X-Apple-Session-ID": str(uuid4()),
        }

        return await self.rtsp.connection.post(
            "/play",
            headers=HEADERS,
            body=plistlib.dumps(
                body,
                fmt=plistlib.FMT_BINARY,  # pylint: disable=no-member
            ),
            allow_error=True,
        )
