from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
KEY_DIR = ROOT_DIR / "config" / "keys"

SCORE_THRESHOLD = 60
HOSTNAME_PENALTY = 15
RANDOM_STATE = 42

HMAC_KEY_FILE = KEY_DIR / "source.key"
