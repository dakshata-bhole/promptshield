import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """
    Central configuration for Prompt Shield.
    Sensitive values are loaded from environment variables.
    """

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "prompt-shield-development-secret"
    )

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    GEMINI_MODEL = os.getenv(
        "GEMINI_MODEL",
        "gemini-3.6-flash"
    )

    DATABASE_PATH = os.getenv(
        "DATABASE_PATH",
        "database/prompt_shield.db"
    )

    OPTIMIZE_THRESHOLD = int(
        os.getenv("OPTIMIZE_THRESHOLD", "40")
    )

    MAX_PROMPT_LENGTH = 10000

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    @classmethod
    def validate(cls):
        """
        Validate the application configuration.
        """

        if not cls.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is missing. "
                "Add it to the .env file."
            )

        if cls.MAX_PROMPT_LENGTH <= 0:
            raise ValueError(
                "MAX_PROMPT_LENGTH must be greater than zero."
            )