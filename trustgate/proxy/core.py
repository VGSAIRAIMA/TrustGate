"""TrustGate raw passthrough proxy core.

Bridges stdio communication between an MCP client (agent) and an MCP server subprocess.
In Stage 4, this is a pure zero-inspection passthrough.
"""

import asyncio
import os
import shlex
import shutil
import sys
import threading


class StdioProxy:
    """Bidirectional stdio proxy between client stdin/stdout and child server process."""

    def __init__(self, target_cmd: str):
        self.target_cmd = target_cmd
        self.proc: asyncio.subprocess.Process | None = None
        self.stdin_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._stop_event = threading.Event()

    def _stdin_reader(self) -> None:
        """Dedicated background thread to read sys.stdin without blocking asyncio.

        Required on Windows where asyncio's Proactor loop cannot attach to standard
        console stdin handles with connect_read_pipe.
        """
        try:
            while not self._stop_event.is_set():
                line = sys.stdin.readline()
                if not line:
                    if self.loop and self.loop.is_running():
                        self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, None)
                    break
                if self.loop and self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, line)
        except Exception:
            if self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.stdin_queue.put_nowait, None)

    async def forward_inbound(self) -> None:
        """Forward client stdin lines to server process stdin."""
        while True:
            line = await self.stdin_queue.get()
            if line is None:
                # Client closed stdin (EOF)
                if self.proc and self.proc.stdin and not self.proc.stdin.is_closing():
                    try:
                        self.proc.stdin.close()
                        await self.proc.stdin.wait_closed()
                    except Exception:
                        pass
                break

            if self.proc and self.proc.stdin and not self.proc.stdin.is_closing():
                data = line.encode("utf-8") if isinstance(line, str) else line
                self.proc.stdin.write(data)
                await self.proc.stdin.drain()

    async def forward_outbound(self) -> None:
        """Forward server process stdout lines to client stdout."""
        if not self.proc or not self.proc.stdout:
            return
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            # Direct unmodified passthrough with immediate flush
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def forward_stderr(self) -> None:
        """Forward server process stderr to client stderr."""
        if not self.proc or not self.proc.stderr:
            return
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def run(self) -> int:
        """Launch target MCP server and run bidirectional stdio passthrough."""
        self.loop = asyncio.get_running_loop()

        parts = shlex.split(self.target_cmd, posix=(sys.platform != "win32"))
        if not parts:
            raise ValueError("Target command cannot be empty.")

        # Cross-platform resolution for python executable
        if sys.platform == "win32":
            if parts[0].lower() in ("python", "python3") and not shutil.which(parts[0]):
                parts[0] = sys.executable

        self.proc = await asyncio.create_subprocess_exec(
            *parts,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        reader_thread = threading.Thread(target=self._stdin_reader, daemon=True)
        reader_thread.start()

        inbound_task = asyncio.create_task(self.forward_inbound(), name="forward_inbound")
        outbound_task = asyncio.create_task(self.forward_outbound(), name="forward_outbound")
        stderr_task = asyncio.create_task(self.forward_stderr(), name="forward_stderr")

        async def monitor_proc():
            if self.proc:
                await self.proc.wait()
                # Server terminated: unblock inbound if waiting
                if not inbound_task.done():
                    inbound_task.cancel()

        monitor_task = asyncio.create_task(monitor_proc(), name="monitor_proc")

        try:
            # Gather tasks so outbound finishes draining all messages before shutting down
            await asyncio.gather(inbound_task, outbound_task, stderr_task, return_exceptions=True)
        finally:
            self._stop_event.set()
            monitor_task.cancel()
            if self.proc and self.proc.returncode is None:
                try:
                    self.proc.terminate()
                    await self.proc.wait()
                except Exception:
                    pass

        return self.proc.returncode if self.proc and self.proc.returncode is not None else 0
