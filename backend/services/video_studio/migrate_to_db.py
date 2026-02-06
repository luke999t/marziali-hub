import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./martial_arts.db")

from pathlib import Path
from models import ProjectStorage
from database import get_db_session
from db_models import DBProject, DBVideo, DBSkeletonData
from datetime import datetime

def migrate_json_to_db():
    storage = ProjectStorage()
    projects = storage.list_projects()

    print(f"Found {len(projects)} projects to migrate")

    migrated_count = 0
    with get_db_session() as db:
        for project in projects:
            print(f"\nMigrating project: {project.name}")

            db_project = DBProject(
                id=project.id,
                name=project.name,
                description=project.description,
                style=project.style.value if hasattr(project.style, 'value') else project.style,
                status=project.status.value if hasattr(project.status, 'value') else project.status,
                created_by=project.created_by,
                created_at=project.created_at,
                updated_at=project.updated_at
            )

            for video in project.videos:
                print(f"  - Migrating video: {video.metadata.filename}")

                db_video = DBVideo(
                    id=video.id,
                    filename=video.metadata.filename,
                    filepath=video.metadata.filepath,
                    project_id=project.id,
                    status=video.status.value if hasattr(video.status, 'value') else video.status,
                    status_message=video.status_message,
                    maestro_data={
                        "name": video.maestro.name,
                        "style": video.maestro.style.value if hasattr(video.maestro.style, 'value') else video.maestro.style,
                        "experience_years": video.maestro.experience_years,
                        "certification": video.maestro.certification,
                        "bio": video.maestro.bio,
                        "photo_url": video.maestro.photo_url
                    },
                    video_metadata={
                        "filename": video.metadata.filename,
                        "filepath": video.metadata.filepath,
                        "size_bytes": video.metadata.size_bytes,
                        "duration_seconds": video.metadata.duration_seconds,
                        "width": video.metadata.width,
                        "height": video.metadata.height,
                        "fps": video.metadata.fps,
                        "total_frames": video.metadata.total_frames,
                        "codec": video.metadata.codec,
                        "bitrate": video.metadata.bitrate
                    },
                    tags=video.tags,
                    notes=video.notes,
                    uploaded_at=video.metadata.uploaded_at
                )

                if video.skeleton:
                    db_skeleton = DBSkeletonData(
                        video_id=video.id,
                        skeleton_filepath=video.skeleton.skeleton_filepath,
                        total_landmarks=video.skeleton.total_landmarks,
                        frames_processed=video.skeleton.frames_processed,
                        detection_rates=video.skeleton.detection_rates,
                        avg_confidence=video.skeleton.avg_confidence,
                        quality_assessment=video.skeleton.quality_assessment,
                        processing_time_seconds=video.skeleton.processing_time_seconds,
                        extracted_at=video.skeleton.extracted_at
                    )
                    db_video.skeleton_data = db_skeleton

                db_project.videos.append(db_video)

            db.add(db_project)
            migrated_count += 1
            print(f"  ✓ Project migrated with {len(project.videos)} videos")

    print(f"\n✅ Migration complete! Migrated {migrated_count} projects")

if __name__ == "__main__":
    print("Starting JSON to Database migration...")
    migrate_json_to_db()
