from ..services.redis import Redis
from .worker import Worker


class RedisClientWorker(Worker):
    def __init__(self, db=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if db is None:
            db = Redis()
        self.db = db
