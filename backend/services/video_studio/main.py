#!/usr/bin/env python3
"""
🎬 VIDEO STUDIO MAIN ENTRY POINT
🎬 AI_DESCRIPTION: Entry point per Video Studio API service
🎬 AI_BUSINESS: Avvia FastAPI server per video processing
🎬 AI_TEACHING: FastAPI, uvicorn, configuration management
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any

# Aggiungi src al path
sys.path.append(str(Path(__file__).parent))

from video_studio_api import create_video_studio_app
import uvicorn

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('video_studio.log')
    ]
)

logger = logging.getLogger(__name__)

def get_config() -> Dict[str, Any]:
    """
    Ottiene configurazione servizio
    
    Returns:
        Configurazione completa
    """
    # Directory base
    base_dir = Path(__file__).parent.parent
    
    config = {
        # Database
        'workflows_db': str(base_dir / 'data' / 'workflows.db'),
        
        # Directory
        'temp_dir': str(base_dir / 'temp'),
        'output_dir': str(base_dir / 'output'),
        'upload_dir': str(base_dir / 'uploads'),
        'data_dir': str(base_dir / 'data'),
        
        # CORS
        'cors_origins': [
            'http://localhost:3100',  # Frontend
            'http://localhost:3000',  # Alternative frontend
            'http://localhost:8000',  # Streaming service
            'http://localhost:8102',  # Library service
            'http://localhost:8104',  # Auth service
        ],
        
        # Processing
        'max_file_size': 500 * 1024 * 1024,  # 500MB
        'supported_formats': ['.mp4', '.avi', '.mov', '.mkv', '.webm'],
        'quality_presets': {
            'low': {'resolution': (640, 480), 'bitrate': '1M'},
            'medium': {'resolution': (1280, 720), 'bitrate': '2M'},
            'high': {'resolution': (1920, 1080), 'bitrate': '5M'},
            'ultra': {'resolution': (3840, 2160), 'bitrate': '10M'}
        },
        
        # AI Models
        'pose_model_complexity': 2,
        'pose_detection_confidence': 0.5,
        'pose_tracking_confidence': 0.5,
        
        # Translation
        'translation_model': 'Helsinki-NLP/opus-mt-en-it',
        'translation_device': 'auto',  # auto, cpu, cuda
        
        # Avatar
        'avatar_templates_dir': str(base_dir / 'templates' / 'avatars'),
        'avatar_output_format': 'mp4',
        'avatar_quality': 'high',
        
        # Performance
        'parallel_workers': int(os.getenv('PARALLEL_WORKERS', '4')),
        'timeout_minutes': int(os.getenv('TIMEOUT_MINUTES', '60')),
        'checkpoint_interval': 30,
        'retry_attempts': 3,
        
        # Logging
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
        'log_file': 'video_studio.log'
    }
    
    # Crea directory se non esistono
    for dir_key in ['temp_dir', 'output_dir', 'upload_dir', 'data_dir']:
        Path(config[dir_key]).mkdir(parents=True, exist_ok=True)
    
    return config

def main():
    """Main entry point"""
    try:
        logger.info("Starting Video Studio API service...")
        
        # Ottieni configurazione
        config = get_config()
        
        # Crea FastAPI app
        app = create_video_studio_app(config)
        
        # Configurazione server
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', '8001'))
        
        logger.info(f"Video Studio API starting on {host}:{port}")
        logger.info(f"Database: {config['workflows_db']}")
        logger.info(f"Upload dir: {config['upload_dir']}")
        logger.info(f"Output dir: {config['output_dir']}")
        
        # Avvia server
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=config['log_level'].lower(),
            access_log=True,
            reload=False,  # Disabilita reload in produzione
            workers=1  # Single worker per SQLite
        )
        
    except KeyboardInterrupt:
        logger.info("Video Studio API stopped by user")
    except Exception as e:
        logger.error(f"Video Studio API failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

