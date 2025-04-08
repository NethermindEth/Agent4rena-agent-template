"""
Configuration for the Solidity audit agent.
"""
import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # OpenAI API settings
    openai_api_key: str = Field(..., env='OPENAI_API_KEY')
    openai_model: str = Field('gpt-3.5-turbo', env='OPENAI_MODEL')
    api_base_url: Optional[str] = Field(None, env='API_BASE_URL')
    
    # Server settings
    webhook_secret: Optional[str] = Field(None, env='WEBHOOK_SECRET')
    
    # Logging settings
    log_level: str = Field('INFO', env='LOG_LEVEL')
    log_file: str = Field('audit_agent.log', env='LOG_FILE')
    
    # Report settings
    default_report_format: str = Field('text', env='DEFAULT_REPORT_FORMAT')
    
    class Config:
        """Pydantic config."""
        env_file = '.env'
        env_file_encoding = 'utf-8'