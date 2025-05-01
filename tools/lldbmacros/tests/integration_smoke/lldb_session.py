"""Defines the behavior for LLDB local at-desk GDB session."""
import contextlib
import functools
import typing
from pathlib import Path

import lldb


class AtDeskLLDBGdbSession:
    def __init__(self, interpreter):
        self._command_interpreter = interpreter

    def refresh(self):
        macros_base_path = Path(__file__).parent.parent.parent
        self.exec('settings set target.load-script-from-symbol-file false')
        self.exec(f'settings set target.process.python-os-plugin-path {macros_base_path}/core/operating_system.py')
        self.exec(f'command script import {macros_base_path}/xnu.py')
        return self

    @classmethod
    @contextlib.contextmanager
    def create(cls, gdb_remote: typing.Optional[str]) -> 'AtDeskLLDBGdbSession':
        debugger = lldb.SBDebugger.Create()
        command_interpreter = debugger.GetCommandInterpreter()

        session = AtDeskLLDBGdbSession(command_interpreter)
        session.exec('settings set plugin.dynamic-loader.darwin-kernel.load-kexts false')

        session.refresh()
        with session._gdb(gdb_remote):
            yield session

        lldb.SBDebugger.Destroy(debugger)

    @functools.lru_cache(maxsize=5096)
    def exec(self, cmd) -> str:
        # TODO: consider logging.
        print(f'LLDBSession running command: `{cmd}`')
        res = lldb.SBCommandReturnObject()
        self._command_interpreter.HandleCommand(cmd, res)
        if res.Succeeded():
            return res.GetOutput()
        raise RuntimeError(res.GetError())

    @contextlib.contextmanager
    def _gdb(self, remote_gdb: typing.Optional[str] = None) -> 'AtDeskLLDBGdbSession':
        if remote_gdb is None:
            yield self
            return

        self.exec(f'gdb {remote_gdb}')
        yield self
        self.exec('detach')
