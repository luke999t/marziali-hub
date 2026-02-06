from celery import Celery
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    'martial_arts_tasks',
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery_app.task(name='process_video_skeleton')
def process_video_skeleton(video_id: str, video_path: str):
    from skeleton_extraction_holistic import extract_skeleton_from_video
    import json

    output_path = f"skeletons/{video_id}_skeleton.json"

    result = extract_skeleton_from_video(video_path, output_path)

    return {
        "video_id": video_id,
        "skeleton_path": output_path,
        "frames_processed": result.get("total_frames", 0),
        "status": "completed"
    }

@celery_app.task(name='analyze_techniques')
def analyze_techniques(video_id: str, skeleton_path: str):
    from technique_extractor import TechniqueExtractor
    from style_classifier import StyleClassifier
    import json

    with open(skeleton_path, 'r') as f:
        skeleton_data = json.load(f)

    classifier = StyleClassifier()
    extractor = TechniqueExtractor()

    detected_style = classifier.classify(skeleton_data)
    techniques = extractor.extract(skeleton_data, detected_style)

    return {
        "video_id": video_id,
        "detected_style": detected_style,
        "techniques": techniques,
        "technique_count": len(techniques)
    }
