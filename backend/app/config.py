import os
from dotenv import load_dotenv

load_dotenv() # load environment variable from .env

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/whatsapp")