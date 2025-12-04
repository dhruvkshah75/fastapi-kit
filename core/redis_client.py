import redis
from .config import settings

REDIS_HOST = settings.REDIS_HOST
REDIS_PORT = settings.REDIS_PORT

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, 
                           db=0, decode_responses=True)

def get_redis():
    """FastAPI dependency to get the Redis client."""
    return redis_client


""" For two redis instances based on priority: high or low"""
" UNCOMMENT the following code and comment out the upper part "

# import redis
# from .config import settings

# redis_high = redis.Redis(
#     host=settings.REDIS_HOST_HIGH, port=settings.REDIS_PORT_HIGH, 
#     db=0, decode_responses=True
# )

# redis_low = redis.Redis(
#     host=settings.REDIS_HOST_LOW, port=settings.REDIS_PORT_LOW, 
#     db=0, decode_responses=True
# )


# def get_redis_client(priority: str = "low") -> redis.Redis:
#     if priority == "high":
#         return redis_high
#     return redis_low


# def get_redis():
#     return redis_high