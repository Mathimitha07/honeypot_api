import os
from dotenv import load_dotenv

# Loads .env locally (Render env vars still work the same)
load_dotenv()

API_KEY = os.getenv("API_KEY", "").strip()
CALLBACK_URL = os.getenv("CALLBACK_URL", "").strip()

# dev = allow debug routes, prod = disable debug routes
ENV = os.getenv("ENV", "dev").strip().lower()

# Handy flags
IS_PROD = ENV == "prod"
