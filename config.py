import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY", "").strip()
CALLBACK_URL = os.getenv("CALLBACK_URL", "").strip()
ENV = os.getenv("ENV", "prod").strip().lower()  # prod by default
