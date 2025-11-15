from __future__ import annotations

import asyncio
import inspect

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "asyncio: mark async tests to be executed on an event loop",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function):
    test_func = pyfuncitem.obj
    if inspect.iscoroutinefunction(test_func):
        sig = inspect.signature(test_func)
        kwargs = {name: pyfuncitem.funcargs[name] for name in sig.parameters}
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(test_func(**kwargs))
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
        return True
