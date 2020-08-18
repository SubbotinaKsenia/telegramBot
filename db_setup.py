from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import create_engine
import config

Base = declarative_base()


class User(Base):
    """User class, contains telegram_id, name, super_user, token attributes"""

    __tablename__ = 'user'

    telegram_id = Column(Integer, primary_key=True, unique=True)
    name = Column(String, nullable=False)
    super_user = Column(Boolean, nullable=False, default=False)
    token = Column(String, nullable=True)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def setup():
    """Creating a connection to the database,
        check the presence of a superuser in database,
        returns scoped_session object"""

    engine = create_engine(config.SQLALCHEMY_DATABASE_URI, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    Base.metadata.bind = engine

    DBSession = scoped_session(sessionmaker(bind=engine))
    Session = DBSession()
    if Session.query(User).first() is None:
        superUser = User(telegram_id=122473548, name='Ksenia', super_user=True)
        Session.add(superUser)
        Session.commit()
    return DBSession
