import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY", "")
CALLBACK_URL = os.getenv("CALLBACK_URL", "")
