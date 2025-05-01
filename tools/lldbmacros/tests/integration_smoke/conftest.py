import datetime
import shutil

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--use-existing-debugger", action="store_true", default=False,
                     help="Use the existing LLDB debugger (internal).")
    parser.addoption("--gdb-remote", action="store", type=str, default=None, help="GDB remote session.")
    parser.addoption("--extra-ignores", action="store", type=str, default='', help="Extra ignores for macros.")


def pytest_sessionstart(session):
    # Adjusting the terminal width to have enough space for the duration.
    terminal_reporter = session.config.pluginmanager.getplugin("terminalreporter")
    if terminal_reporter:
        full_width = shutil.get_terminal_size().columns
        custom_width = max(int(full_width) - len(' 0:00:00.000000'), 40)  # Ensure a minimum width of 40
        terminal_reporter._tw.fullwidth = custom_width


def pytest_runtest_logreport(report: pytest.TestReport):
    if report.when == "call":
        # Log the duration of test on the fly.
        formatted_duration = str(datetime.timedelta(seconds=report.duration))
        print(f' {formatted_duration}', end='')
