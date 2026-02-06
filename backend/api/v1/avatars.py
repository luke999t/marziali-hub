"""
AI_MODULE: Avatar API
AI_DESCRIPTION: REST API per gestione avatar 3D con bone mapping MediaPipe
AI_TEACHING: Questo router gestisce il ciclo di vita completo degli avatar:
             - CRUD avatar (lista, dettaglio, upload, update, delete)
             - Download file GLB per rendering 3D
             - Bone mapping per connettere skeleton MediaPipe agli avatar
             - Applicazione skeleton data per generare animazioni
             I modelli GLB vengono serviti come streaming per performance ottimali.
"""

import os
import uuid
import logging
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, File, Form,
    Query, status
)
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import aiofiles

from core.database import get_db
from core.security import get_current_user, get_current_admin_user, get_optional_user
from models.avatar import Avatar, AvatarStyle, AvatarRigType, AvatarLicenseType
from schemas.avatar import (
    AvatarCreate, AvatarUpdate, AvatarResponse, AvatarDetailResponse,
    AvatarListResponse, BoneMappingResponse, ApplySkeletonRequest,
    ApplySkeletonResponse, AvatarStylesResponse, AvatarStyleInfo,
)
from services.avatar_service import AvatarService, AVATAR_STORAGE_PATH

logger = logging.getLogger(__name__)

router = APIRouter()
avatar_service = AvatarService()

# Dimensione massima file GLB: 50MB
MAX_FILE_SIZE = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {".glb", ".gltf"}


# =========================================================================
# STATIC ROUTES (must be defined BEFORE /{avatar_id} to avoid matching)
# =========================================================================

@router.get(
    "/bone-mapping",
    response_model=BoneMappingResponse,
    summary="Mapping MediaPipe -> bones",
    description="Ritorna il mapping standard tra i 75 landmarks MediaPipe Holistic e i bones avatar."
)
async def get_bone_mapping():
    """
    WHY endpoint pubblico senza autenticazione:
    Il bone mapping e' informazione statica e pubblica.
    Il frontend lo usa per disegnare l'overlay skeleton
    sull'avatar 3D anche senza dati di animazione.
    """
    mapping = avatar_service.get_bone_mapping()
    return BoneMappingResponse(**mapping)


@router.get(
    "/styles",
    response_model=AvatarStylesResponse,
    summary="Lista stili marziali",
    description="Ritorna gli stili marziali disponibili per filtro avatar."
)
async def get_avatar_styles(
    db: AsyncSession = Depends(get_db),
):
    """Ritorna gli stili con conteggio avatar per ciascuno"""
    from sqlalchemy import cast, String

    styles_info = avatar_service.get_available_styles()

    # Conta avatar per stile (usa cast per compatibilita' VARCHAR/Enum)
    for style_info in styles_info:
        count_query = select(func.count(Avatar.id)).where(
            and_(
                cast(Avatar.style, String) == style_info["value"],
                Avatar.is_active == True,
                Avatar.is_public == True,
            )
        )
        result = await db.execute(count_query)
        style_info["avatar_count"] = result.scalar() or 0

    return AvatarStylesResponse(
        styles=[AvatarStyleInfo(**s) for s in styles_info]
    )


# =========================================================================
# 1. GET /avatars/ - Lista avatar disponibili
# =========================================================================

@router.get(
    "/",
    response_model=AvatarListResponse,
    summary="Lista avatar disponibili",
    description="Ritorna avatar pubblici + owned dall'utente. Supporta filtro per stile e paginazione."
)
async def list_avatars(
    style: Optional[str] = Query(None, description="Filtra per stile marziale"),
    page: int = Query(1, ge=1, description="Pagina"),
    page_size: int = Query(20, ge=1, le=100, description="Elementi per pagina"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_optional_user),
):
    """
    WHY filtro is_active=True di default:
    Gli avatar soft-deleted non devono apparire nella lista.
    Solo gli admin vedono avatar inattivi (via admin panel separato).
    """
    # Costruisci query base: avatar attivi e (pubblici OR owned dall'utente)
    conditions = [Avatar.is_active == True]

    if current_user:
        conditions.append(
            (Avatar.is_public == True) | (Avatar.created_by == current_user.id)
        )
    else:
        conditions.append(Avatar.is_public == True)

    if style:
        from sqlalchemy import cast, String
        # Valida stile prima di usarlo
        try:
            AvatarStyle(style)  # Verifica che lo stile esista
            # Usa cast per compatibilita' VARCHAR/Enum
            conditions.append(cast(Avatar.style, String) == style)
        except ValueError:
            # Stile non valido - ritorna lista vuota
            return AvatarListResponse(avatars=[], total=0, page=page, page_size=page_size)

    # Count totale per paginazione
    count_query = select(func.count(Avatar.id)).where(and_(*conditions))
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Query paginata
    offset = (page - 1) * page_size
    query = (
        select(Avatar)
        .where(and_(*conditions))
        .order_by(Avatar.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(query)
    avatars = result.scalars().all()

    return AvatarListResponse(
        avatars=[AvatarResponse.model_validate(a) for a in avatars],
        total=total,
        page=page,
        page_size=page_size,
    )


# =========================================================================
# 2. GET /avatars/{avatar_id} - Dettaglio singolo avatar
# =========================================================================

@router.get(
    "/{avatar_id}",
    response_model=AvatarDetailResponse,
    summary="Dettaglio avatar",
    description="Ritorna info complete di un avatar incluso bone mapping e file size."
)
async def get_avatar(
    avatar_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_optional_user),
):
    avatar = await _get_avatar_or_404(db, avatar_id, current_user)
    return AvatarDetailResponse.model_validate(avatar)


# =========================================================================
# 3. POST /avatars/ - Upload nuovo avatar (admin only)
# =========================================================================

@router.post(
    "/",
    response_model=AvatarDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload nuovo avatar (admin)",
    description="Carica un nuovo modello 3D GLB/GLTF. Max 50MB."
)
async def create_avatar(
    file: UploadFile = File(..., description="File GLB/GLTF del modello 3D"),
    name: str = Form(..., min_length=1, max_length=100),
    description: Optional[str] = Form(None),
    style: str = Form("generic"),
    rig_type: str = Form("readyplayerme"),
    license_type: str = Form("cc_by"),
    attribution: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    admin_user=Depends(get_current_admin_user),
):
    """
    WHY validazione estensione + dimensione:
    - Estensione: solo GLB/GLTF per compatibilita' con Three.js/model-viewer
    - Dimensione: 50MB max per non sovraccaricare storage e download mobile
    """
    # Valida estensione
    file_ext = Path(file.filename).suffix.lower() if file.filename else ""
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato non supportato: {file_ext}. Formati accettati: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Valida dimensione leggendo il contenuto
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File troppo grande: {len(content) / (1024*1024):.1f}MB. Max: {MAX_FILE_SIZE / (1024*1024):.0f}MB"
        )

    # Genera filename univoco per evitare collisioni
    file_id = str(uuid.uuid4())
    filename = f"{file_id}{file_ext}"
    save_path = AVATAR_STORAGE_PATH / "models" / filename

    # Assicurati che la directory esista
    save_path.parent.mkdir(parents=True, exist_ok=True)

    # Salva file
    async with aiofiles.open(save_path, 'wb') as f:
        await f.write(content)

    logger.info(f"Avatar file saved: {save_path} ({len(content)} bytes)")

    # Valida stile
    try:
        avatar_style = AvatarStyle(style)
    except ValueError:
        avatar_style = AvatarStyle.GENERIC

    # Valida rig type
    try:
        avatar_rig = AvatarRigType(rig_type)
    except ValueError:
        avatar_rig = AvatarRigType.READYPLAYERME

    # Valida license type
    try:
        avatar_license = AvatarLicenseType(license_type)
    except ValueError:
        avatar_license = AvatarLicenseType.CC_BY

    # Crea record nel database
    avatar = Avatar(
        name=name,
        description=description,
        style=avatar_style,
        model_url=f"/api/v1/avatars/{file_id}/file",
        file_size_bytes=len(content),
        rig_type=avatar_rig,
        has_hand_bones=True,
        is_public=True,
        is_active=True,
        license_type=avatar_license,
        attribution=attribution,
        created_by=admin_user.id,
    )

    db.add(avatar)
    await db.commit()
    await db.refresh(avatar)

    logger.info(f"Avatar created: id={avatar.id}, name={name}")
    return AvatarDetailResponse.model_validate(avatar)


# =========================================================================
# 4. PUT /avatars/{avatar_id} - Update metadata (admin only)
# =========================================================================

@router.put(
    "/{avatar_id}",
    response_model=AvatarDetailResponse,
    summary="Aggiorna avatar (admin)",
    description="Aggiorna nome, descrizione e stile di un avatar."
)
async def update_avatar(
    avatar_id: str,
    update_data: AvatarUpdate,
    db: AsyncSession = Depends(get_db),
    admin_user=Depends(get_current_admin_user),
):
    avatar = await _get_avatar_or_404(db, avatar_id, admin_user)

    # Applica solo campi forniti (non-None)
    if update_data.name is not None:
        avatar.name = update_data.name
    if update_data.description is not None:
        avatar.description = update_data.description
    if update_data.style is not None:
        try:
            avatar.style = AvatarStyle(update_data.style)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Stile non valido: {update_data.style}"
            )

    await db.commit()
    await db.refresh(avatar)

    logger.info(f"Avatar updated: id={avatar.id}")
    return AvatarDetailResponse.model_validate(avatar)


# =========================================================================
# 5. DELETE /avatars/{avatar_id} - Soft delete (admin only)
# =========================================================================

@router.delete(
    "/{avatar_id}",
    status_code=status.HTTP_200_OK,
    summary="Elimina avatar (admin)",
    description="Soft delete: l'avatar viene disattivato ma non cancellato dal disco."
)
async def delete_avatar(
    avatar_id: str,
    db: AsyncSession = Depends(get_db),
    admin_user=Depends(get_current_admin_user),
):
    """
    WHY soft delete e non hard delete:
    - L'avatar potrebbe essere riferito da sessioni di analisi salvate
    - Il file GLB resta su disco per eventuale ripristino
    - L'admin puo' riattivarlo se necessario
    """
    avatar = await _get_avatar_or_404(db, avatar_id, admin_user)
    avatar.is_active = False
    await db.commit()

    logger.info(f"Avatar soft-deleted: id={avatar.id}, name={avatar.name}")
    return {"message": f"Avatar '{avatar.name}' disattivato", "id": str(avatar.id)}


# =========================================================================
# 6. GET /avatars/{avatar_id}/file - Download file GLB
# =========================================================================

@router.get(
    "/{avatar_id}/file",
    summary="Download modello 3D",
    description="Streaming download del file GLB per rendering 3D nel viewer.",
    response_class=FileResponse,
)
async def download_avatar_file(
    avatar_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    WHY FileResponse e non StreamingResponse:
    FileResponse gestisce automaticamente Content-Length, Range requests
    e caching headers. Essenziale per il model-viewer che fa range requests
    per caricare solo le parti necessarie del GLB.
    """
    avatar = await _get_avatar_or_404(db, avatar_id, None)

    # Trova il file nel filesystem
    model_dir = AVATAR_STORAGE_PATH / "models"
    model_files = []

    if model_dir.exists():
        # 1. Prova con avatar_id diretto
        model_files = list(model_dir.glob(f"{avatar_id}.*"))

        # 2. Prova con UUID dell'avatar
        if not model_files:
            model_files = list(model_dir.glob(f"{str(avatar.id)}.*"))

        # 3. Cerca per nome avatar (converte spazi in underscore)
        if not model_files:
            name_pattern = avatar.name.lower().replace(' ', '_')
            model_files = list(model_dir.glob(f"*{name_pattern}*"))

        # 4. Cerca per prima parola del nome (es. "male" o "female")
        if not model_files:
            first_word = avatar.name.lower().split()[0]
            model_files = list(model_dir.glob(f"{first_word}*"))

        # 5. Fallback: cerca per nome nel model_url
        if not model_files:
            url_path = avatar.model_url or ""
            if "/" in url_path:
                potential_id = url_path.rstrip("/").split("/")[-2]
                model_files = list(model_dir.glob(f"{potential_id}.*"))

    if not model_files:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File modello non trovato sul filesystem"
        )

    file_path = model_files[0]
    media_type = "model/gltf-binary" if file_path.suffix == ".glb" else "model/gltf+json"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=f"{avatar.name.replace(' ', '_')}{file_path.suffix}",
    )


# =========================================================================
# 7. POST /avatars/{avatar_id}/apply-skeleton - Applica skeleton all'avatar
# =========================================================================

@router.post(
    "/{avatar_id}/apply-skeleton",
    response_model=ApplySkeletonResponse,
    summary="Applica skeleton all'avatar",
    description="Mappa 75 landmarks MediaPipe sui bones dell'avatar, generando bone transforms."
)
async def apply_skeleton(
    avatar_id: str,
    request: ApplySkeletonRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    WHY endpoint separato da GET skeleton:
    L'applicazione dello skeleton all'avatar richiede:
    1. Validare che l'avatar esista e sia compatibile
    2. Recuperare i dati skeleton (potenzialmente da altro microservizio)
    3. Calcolare i bone transforms (operazione CPU-intensive)
    4. Ritornare i risultati nel formato giusto per il 3D viewer

    Il frontend chiama questo endpoint quando l'utente seleziona
    un avatar e vuole visualizzare una posa.
    """
    avatar = await _get_avatar_or_404(db, avatar_id, current_user)

    # TODO: Recupera skeleton data dalla Skeleton API
    # Per ora, accetta skeleton_data inline nel body come workaround
    # In produzione: chiamata interna alla Skeleton API
    skeleton_data = {
        "skeleton_id": str(request.skeleton_id),
        "frames": [],  # Placeholder - verrà popolato dalla Skeleton API
    }

    result = await avatar_service.apply_skeleton_to_avatar(
        avatar_id=avatar.id,
        skeleton_data=skeleton_data,
        frame_number=request.frame_number,
    )

    return ApplySkeletonResponse(
        avatar_id=result["avatar_id"],
        skeleton_id=result["skeleton_id"],
        frame_count=result["frame_count"],
        bone_transforms=result["bone_transforms"],
    )


# =========================================================================
# HELPERS
# =========================================================================

async def _get_avatar_or_404(
    db: AsyncSession,
    avatar_id: str,
    current_user,
) -> Avatar:
    """
    Recupera un avatar dal database o ritorna 404.

    WHY check is_active:
    Avatar soft-deleted non devono essere accessibili
    nemmeno se si conosce l'ID diretto.
    """
    try:
        avatar_uuid = uuid.UUID(avatar_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID avatar non valido"
        )

    result = await db.execute(
        select(Avatar).where(
            and_(Avatar.id == avatar_uuid, Avatar.is_active == True)
        )
    )
    avatar = result.scalar_one_or_none()

    if not avatar:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Avatar non trovato: {avatar_id}"
        )

    # Verifica accesso: avatar pubblico o owned dall'utente
    if not avatar.is_public:
        if not current_user or (avatar.created_by and avatar.created_by != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Non hai accesso a questo avatar"
            )

    return avatar
