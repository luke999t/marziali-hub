"""
================================================================================
AI_MODULE: Video & LiveEvent Test Fixtures
AI_VERSION: 1.0.0
AI_DESCRIPTION: Fixtures pytest per Video e LiveEvent
AI_BUSINESS: Test content catalog, streaming, moderation
AI_TEACHING: Fixtures per entità multimediali con metadati complessi

================================================================================

FIXTURES:
- test_video: Crea Video di test con metadati completi
- test_video_id: Ritorna solo l'ID del video
- test_live_event: Crea LiveEvent schedulato
- test_live_event_id: Ritorna solo l'ID dell'evento

DEPENDENCIES:
- test_db: Session database sync
- test_maestro: Maestro per ownership LiveEvent
================================================================================
"""

import pytest
import uuid
from datetime import datetime, timedelta
from typing import Optional


@pytest.fixture(scope="function")
def test_video(test_db):
    """
    🎬 FIXTURE: Crea Video di test con metadati completi.

    🎓 AI_BUSINESS: Video è il contenuto principale della piattaforma.
    🎓 AI_TEACHING: Include tutti i campi per test esaustivi.

    Returns:
        Video: Video con dati realistici
    """
    from models.video import Video, VideoStatus, VideoCategory, Difficulty

    unique_id = uuid.uuid4().hex[:8]

    video = Video(
        id=uuid.uuid4(),
        title=f"Tai Chi Yang Form - Test {unique_id}",
        description="Video di test per la forma Yang del Tai Chi Chuan. "
                    "Include movimenti lenti e fluidi tipici dello stile Yang.",
        slug=f"tai-chi-yang-form-test-{unique_id}",
        category=VideoCategory.TECHNIQUE,
        style="Tai Chi Chuan",
        difficulty=Difficulty.INTERMEDIATE,
        tags=["tai chi", "yang", "form", "test"],
        thumbnail_url=f"https://cdn.test.com/thumbnails/{unique_id}.jpg",
        video_url=f"https://cdn.test.com/videos/{unique_id}.mp4",
        hls_playlist_url=f"https://cdn.test.com/hls/{unique_id}/master.m3u8",
        duration=1800,  # 30 minuti
        file_size=500000000,  # ~500MB
        quality_available=["360p", "720p", "1080p"],
        hls_variants={
            "360p": f"https://cdn.test.com/hls/{unique_id}/360p.m3u8",
            "720p": f"https://cdn.test.com/hls/{unique_id}/720p.m3u8",
            "1080p": f"https://cdn.test.com/hls/{unique_id}/1080p.m3u8"
        },
        has_subtitles=True,
        available_languages=["it", "en", "es"],
        subtitle_urls={
            "it": f"https://cdn.test.com/subs/{unique_id}_it.vtt",
            "en": f"https://cdn.test.com/subs/{unique_id}_en.vtt",
            "es": f"https://cdn.test.com/subs/{unique_id}_es.vtt"
        },
        view_count=150,
        unique_viewers=100,
        avg_watch_time=1200,  # 20 minuti
        completion_rate=0.75,
        likes_count=45,
        tier_required="free",
        is_premium=False,
        is_public=True,
        is_featured=True,
        instructor_name="Maestro Test Yang",
        instructor_bio="Esperto di Tai Chi Yang style con 20 anni di esperienza.",
        status=VideoStatus.READY,
        created_at=datetime.utcnow() - timedelta(days=30),
        updated_at=datetime.utcnow(),
        published_at=datetime.utcnow() - timedelta(days=29)
    )

    test_db.add(video)
    test_db.commit()
    test_db.refresh(video)

    print(f"\n[FIXTURE test_video] Created Video: {video.id} - {video.title}")

    yield video

    # Cleanup
    try:
        test_db.delete(video)
        test_db.commit()
        print(f"[FIXTURE test_video] Cleaned up Video: {video.id}")
    except Exception as e:
        print(f"[FIXTURE test_video] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="function")
def test_video_premium(test_db):
    """
    💎 FIXTURE: Crea Video PREMIUM di test.

    🎓 AI_BUSINESS: Video premium richiede subscription per accesso.

    Returns:
        Video: Video con tier_required="premium"
    """
    from models.video import Video, VideoStatus, VideoCategory, Difficulty

    unique_id = uuid.uuid4().hex[:8]

    video = Video(
        id=uuid.uuid4(),
        title=f"Advanced Karate Kata - Premium Test {unique_id}",
        description="Kata avanzato di Karate per utenti premium.",
        slug=f"advanced-karate-kata-premium-{unique_id}",
        category=VideoCategory.KATA,
        style="Karate Shotokan",
        difficulty=Difficulty.ADVANCED,
        tags=["karate", "kata", "advanced", "premium"],
        thumbnail_url=f"https://cdn.test.com/thumbnails/premium_{unique_id}.jpg",
        video_url=f"https://cdn.test.com/videos/premium_{unique_id}.mp4",
        duration=2700,  # 45 minuti
        tier_required="premium",
        is_premium=True,
        is_public=True,
        status=VideoStatus.READY,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        published_at=datetime.utcnow()
    )

    test_db.add(video)
    test_db.commit()
    test_db.refresh(video)

    print(f"\n[FIXTURE test_video_premium] Created Premium Video: {video.id}")

    yield video

    # Cleanup
    try:
        test_db.delete(video)
        test_db.commit()
    except Exception:
        test_db.rollback()


@pytest.fixture(scope="function")
def test_video_id(test_video) -> str:
    """
    🆔 FIXTURE: Ritorna solo l'ID del video di test.

    Returns:
        str: UUID del video come stringa
    """
    return str(test_video.id)


@pytest.fixture(scope="function")
def test_live_event(test_db, test_maestro_with_user):
    """
    📺 FIXTURE: Crea LiveEvent schedulato di test.

    🎓 AI_BUSINESS: LiveEvent è un evento streaming con donazioni.
    🎓 AI_TEACHING: Richiede Maestro owner.

    Dependencies:
        - test_maestro_with_user: Maestro che ospita l'evento

    Returns:
        LiveEvent: Evento schedulato per domani
    """
    from models.video import LiveEvent, LiveEventType, LiveEventStatus

    user, maestro = test_maestro_with_user
    unique_id = uuid.uuid4().hex[:8]

    live_event = LiveEvent(
        id=uuid.uuid4(),
        maestro_id=maestro.id,
        instructor_id=user.id,  # Backward compat
        title=f"Live Tai Chi Class - Test {unique_id}",
        description="Lezione live di Tai Chi per principianti. "
                    "Impara le basi della forma Yang.",
        event_type=LiveEventType.LIVE_CLASS,
        stream_key=f"stream_key_{unique_id}",
        rtmp_url=f"rtmp://stream.test.com/live/{unique_id}",
        hls_url=f"https://cdn.test.com/live/{unique_id}/master.m3u8",
        status=LiveEventStatus.SCHEDULED,
        is_active=False,
        scheduled_start=datetime.utcnow() + timedelta(days=1),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    test_db.add(live_event)
    test_db.commit()
    test_db.refresh(live_event)

    print(f"\n[FIXTURE test_live_event] Created LiveEvent: {live_event.id} - {live_event.title}")

    yield live_event

    # Cleanup
    try:
        test_db.delete(live_event)
        test_db.commit()
        print(f"[FIXTURE test_live_event] Cleaned up LiveEvent: {live_event.id}")
    except Exception as e:
        print(f"[FIXTURE test_live_event] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="function")
def test_live_event_active(test_db, test_maestro_with_user):
    """
    🔴 FIXTURE: Crea LiveEvent attivo (in streaming).

    🎓 AI_BUSINESS: Evento live in corso per test real-time.

    Returns:
        LiveEvent: Evento con status=LIVE
    """
    from models.video import LiveEvent, LiveEventType, LiveEventStatus

    user, maestro = test_maestro_with_user
    unique_id = uuid.uuid4().hex[:8]

    live_event = LiveEvent(
        id=uuid.uuid4(),
        maestro_id=maestro.id,
        instructor_id=user.id,
        title=f"LIVE NOW: Karate Training - {unique_id}",
        description="Allenamento di Karate in diretta!",
        event_type=LiveEventType.LIVE_CLASS,
        stream_key=f"live_stream_{unique_id}",
        rtmp_url=f"rtmp://stream.test.com/live/{unique_id}",
        hls_url=f"https://cdn.test.com/live/{unique_id}/master.m3u8",
        status=LiveEventStatus.LIVE,
        is_active=True,
        scheduled_start=datetime.utcnow() - timedelta(hours=1),
        created_at=datetime.utcnow() - timedelta(hours=2),
        updated_at=datetime.utcnow()
    )

    test_db.add(live_event)
    test_db.commit()
    test_db.refresh(live_event)

    print(f"\n[FIXTURE test_live_event_active] Created LIVE event: {live_event.id}")

    yield live_event

    # Cleanup
    try:
        test_db.delete(live_event)
        test_db.commit()
    except Exception:
        test_db.rollback()


@pytest.fixture(scope="function")
def test_live_event_id(test_live_event) -> str:
    """
    🆔 FIXTURE: Ritorna solo l'ID del LiveEvent.

    Returns:
        str: UUID del LiveEvent come stringa
    """
    return str(test_live_event.id)


@pytest.fixture(scope="function")
def multiple_test_videos(test_db):
    """
    📚 FIXTURE: Crea multiple Video per test pagination.

    🎓 AI_TEACHING: Utile per test di list/pagination endpoints.

    Returns:
        list: Lista di 5 Video
    """
    from models.video import Video, VideoStatus, VideoCategory, Difficulty

    videos = []
    categories = [VideoCategory.TECHNIQUE, VideoCategory.KATA, VideoCategory.COMBAT,
                  VideoCategory.THEORY, VideoCategory.WORKOUT]
    difficulties = [Difficulty.BEGINNER, Difficulty.INTERMEDIATE, Difficulty.ADVANCED,
                    Difficulty.EXPERT, Difficulty.INTERMEDIATE]

    for i in range(5):
        unique_id = uuid.uuid4().hex[:8]
        video = Video(
            id=uuid.uuid4(),
            title=f"Test Video {i+1} - {unique_id}",
            description=f"Video di test numero {i+1}",
            slug=f"test-video-{i+1}-{unique_id}",
            category=categories[i],
            difficulty=difficulties[i],
            video_url=f"https://cdn.test.com/videos/test_{i}_{unique_id}.mp4",
            duration=600 + (i * 300),  # 10-25 minuti
            tier_required="free" if i < 3 else "premium",
            is_premium=i >= 3,
            is_public=True,
            status=VideoStatus.READY,
            view_count=100 - (i * 15),
            created_at=datetime.utcnow() - timedelta(days=i * 7),
            updated_at=datetime.utcnow()
        )
        test_db.add(video)
        videos.append(video)

    test_db.commit()
    for v in videos:
        test_db.refresh(v)

    print(f"\n[FIXTURE multiple_test_videos] Created {len(videos)} videos")

    yield videos

    # Cleanup
    try:
        for video in videos:
            test_db.delete(video)
        test_db.commit()
        print(f"[FIXTURE multiple_test_videos] Cleaned up {len(videos)} videos")
    except Exception as e:
        print(f"[FIXTURE multiple_test_videos] Cleanup failed: {e}")
        test_db.rollback()
