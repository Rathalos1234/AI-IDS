import os, json
from typing import Dict, Any
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

class Bus:
    def __init__(self):
        self.r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
#not sure what to use for maxlen just put 5k for now it will just delete older stuff
    def publish(self, stream: str, data: Dict[str, Any]):
        self.r.xadd(stream, {"data": json.dumps(data)}, maxlen=5000, approximate=True)
    def consume(self, stream: str, group: str, consumer: str, block_ms: int = 2000):
        try:
            self.r.xgroup_create(stream, group, id="$", mkstream=True)
        except redis.ResponseError:
            pass
        while True:
            resp = self.r.xreadgroup(group, consumer, streams={stream: ">"}, count=10, block=block_ms)
            if not resp:
                continue
            for _, messages in resp:
                for msg_id, fields in messages:
                    payload = json.loads(fields.get("data","{}"))
                    yield msg_id, payload
                    self.r.xack(stream, group, msg_id)

#singleton
bus = Bus()
