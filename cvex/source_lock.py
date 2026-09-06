"""One source lease shared by CLI ingestion and scheduled workers."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

from sqlalchemy import text

_held = ContextVar("source_leases", default=frozenset())
LOCK_IDS = {"cve": 7401010, "nvd": 7401011}


@contextmanager
def source_lock(engine, source):
    key = (str(engine.url), source)
    if key in _held.get():
        yield
        return
    with engine.connect() as connection:
        acquired = connection.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_IDS[source]}).scalar()
        connection.commit()
        if not acquired:
            raise RuntimeError(f"{source} ingestion is already running; retry later")
        token = _held.set(_held.get() | {key})
        try:
            yield
        finally:
            _held.reset(token)
            try:
                connection.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": LOCK_IDS[source]})
                connection.commit()
            except Exception:
                connection.invalidate()
                raise


def exclusive_source(source):
    def decorate(function):
        @wraps(function)
        def wrapped(session, *args, **kwargs):
            with source_lock(session.get_bind(), source):
                return function(session, *args, **kwargs)
        return wrapped
    return decorate
