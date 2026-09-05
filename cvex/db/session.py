from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cvex.config import CvexConfig


def make_engine(config: CvexConfig):
    return create_engine(config.database.url, future=True)


def make_session_factory(config: CvexConfig) -> sessionmaker[Session]:
    return sessionmaker(bind=make_engine(config), expire_on_commit=False, future=True)
