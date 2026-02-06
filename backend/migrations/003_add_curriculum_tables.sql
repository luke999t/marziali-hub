-- """
-- 🎓 AI_MODULE: Curriculum Database Migration
-- 🎓 AI_DESCRIPTION: Creates all curriculum-related tables for martial arts progression system
-- 🎓 AI_BUSINESS: Enables structured learning paths with levels, requirements, and certifications
-- 🎓 AI_TEACHING: Relational database design with proper foreign keys and constraints
--
-- 🔄 ALTERNATIVE_VALUTATE: Document-based (MongoDB), Graph DB (Neo4j)
-- 💡 PERCHÉ_QUESTA_SOLUZIONE: Relational integrity for complex requirements, SQL compatibility
-- 📊 METRICHE_SUCCESSO: Complete curriculum tracking, exam submissions, certificates
-- """

-- Migration: 003_add_curriculum_tables
-- Date: 2025-12-06
-- Description: Add curriculum, levels, requirements, progress, exams, certificates tables

-- =============================================================================
-- CURRICULA - Main curriculum definitions (e.g., "Karate Shotokan", "Judo")
-- =============================================================================
CREATE TABLE IF NOT EXISTS curricula (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Basic info
    name VARCHAR(255) NOT NULL,
    description TEXT,
    martial_art VARCHAR(100) NOT NULL,  -- e.g., "Karate", "Judo", "Aikido"
    style VARCHAR(100),  -- e.g., "Shotokan", "Goju-Ryu"

    -- Ownership
    maestro_id UUID REFERENCES maestros(id) ON DELETE SET NULL,
    asd_id UUID REFERENCES asds(id) ON DELETE SET NULL,

    -- Configuration
    is_public BOOLEAN DEFAULT false,
    is_official BOOLEAN DEFAULT false,  -- Official federation curriculum
    max_levels INTEGER DEFAULT 10,

    -- Media
    cover_image_url VARCHAR(512),

    -- Stats
    total_students INTEGER DEFAULT 0,
    total_completions INTEGER DEFAULT 0,
    average_completion_days INTEGER,

    -- Status
    status VARCHAR(20) DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT curricula_name_martial_art_unique UNIQUE (name, martial_art, style)
);

CREATE INDEX idx_curricula_martial_art ON curricula(martial_art);
CREATE INDEX idx_curricula_maestro_id ON curricula(maestro_id);
CREATE INDEX idx_curricula_status ON curricula(status);

-- =============================================================================
-- CURRICULUM_LEVELS - Individual levels/belts within a curriculum
-- =============================================================================
CREATE TABLE IF NOT EXISTS curriculum_levels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationship
    curriculum_id UUID NOT NULL REFERENCES curricula(id) ON DELETE CASCADE,

    -- Level info
    level_number INTEGER NOT NULL,  -- 1, 2, 3... or belt order
    name VARCHAR(255) NOT NULL,  -- e.g., "White Belt", "Yellow Belt", "1° Kyu"
    japanese_name VARCHAR(255),  -- e.g., "Shiro Obi", "Ikkyu"
    description TEXT,

    -- Color (for belt visualization)
    belt_color VARCHAR(50),  -- e.g., "#FFFFFF", "white"
    secondary_color VARCHAR(50),  -- For striped belts

    -- Requirements summary
    minimum_months_training INTEGER DEFAULT 0,
    minimum_age INTEGER,  -- Minimum age for this level

    -- Media
    badge_image_url VARCHAR(512),

    -- Stats
    total_requirements INTEGER DEFAULT 0,
    total_students_at_level INTEGER DEFAULT 0,
    average_completion_days INTEGER,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT curriculum_levels_unique_order UNIQUE (curriculum_id, level_number)
);

CREATE INDEX idx_curriculum_levels_curriculum_id ON curriculum_levels(curriculum_id);

-- =============================================================================
-- CURRICULUM_REQUIREMENTS - Individual requirements for each level
-- =============================================================================
CREATE TABLE IF NOT EXISTS curriculum_requirements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationship
    level_id UUID NOT NULL REFERENCES curriculum_levels(id) ON DELETE CASCADE,

    -- Requirement info
    requirement_type VARCHAR(50) NOT NULL CHECK (requirement_type IN (
        'KATA',           -- Perform a specific kata
        'TECHNIQUE',      -- Demonstrate a technique
        'COMBINATION',    -- Perform a combination
        'KUMITE',         -- Sparring requirement
        'THEORY',         -- Written/oral exam
        'ATTENDANCE',     -- Minimum training sessions
        'VIDEO_UPLOAD',   -- Upload video demonstration
        'LIVE_DEMO'       -- Live demonstration to maestro
    )),

    -- Content
    name VARCHAR(255) NOT NULL,
    description TEXT,
    japanese_name VARCHAR(255),

    -- Requirements
    order_index INTEGER NOT NULL DEFAULT 0,
    is_mandatory BOOLEAN DEFAULT true,
    passing_score INTEGER DEFAULT 70,  -- Minimum score to pass (0-100)

    -- Reference video (maestro demonstration)
    reference_video_id UUID,  -- Link to videos table
    reference_video_url VARCHAR(512),

    -- AI grading configuration
    ai_grading_enabled BOOLEAN DEFAULT true,
    skeleton_comparison_weight FLOAT DEFAULT 0.7,  -- Weight for skeleton matching

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_curriculum_requirements_level_id ON curriculum_requirements(level_id);
CREATE INDEX idx_curriculum_requirements_type ON curriculum_requirements(requirement_type);

-- =============================================================================
-- STUDENT_PROGRESS - Track student progress through curriculum
-- =============================================================================
CREATE TABLE IF NOT EXISTS student_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    curriculum_id UUID NOT NULL REFERENCES curricula(id) ON DELETE CASCADE,
    current_level_id UUID REFERENCES curriculum_levels(id) ON DELETE SET NULL,

    -- Progress
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    current_level_started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_requirements_completed INTEGER DEFAULT 0,
    total_requirements INTEGER DEFAULT 0,

    -- Stats
    total_training_hours FLOAT DEFAULT 0,
    total_sessions INTEGER DEFAULT 0,
    total_exams_passed INTEGER DEFAULT 0,
    average_score FLOAT DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED', 'DROPPED')),
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT student_progress_unique UNIQUE (student_id, curriculum_id)
);

CREATE INDEX idx_student_progress_student_id ON student_progress(student_id);
CREATE INDEX idx_student_progress_curriculum_id ON student_progress(curriculum_id);
CREATE INDEX idx_student_progress_status ON student_progress(status);

-- =============================================================================
-- REQUIREMENT_COMPLETIONS - Track individual requirement completions
-- =============================================================================
CREATE TABLE IF NOT EXISTS requirement_completions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    progress_id UUID NOT NULL REFERENCES student_progress(id) ON DELETE CASCADE,
    requirement_id UUID NOT NULL REFERENCES curriculum_requirements(id) ON DELETE CASCADE,

    -- Completion status
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'IN_PROGRESS', 'SUBMITTED', 'PASSED', 'FAILED', 'RETRYING'
    )),

    -- Scores
    score INTEGER,  -- 0-100
    ai_score INTEGER,  -- AI grading score
    maestro_score INTEGER,  -- Maestro override score
    skeleton_match_score FLOAT,  -- DTW comparison result

    -- Attempts
    attempt_count INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,

    -- Review
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,

    -- Timestamps
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT requirement_completions_unique UNIQUE (progress_id, requirement_id)
);

CREATE INDEX idx_requirement_completions_progress_id ON requirement_completions(progress_id);
CREATE INDEX idx_requirement_completions_status ON requirement_completions(status);

-- =============================================================================
-- EXAM_SUBMISSIONS - Video/content submissions for requirements
-- =============================================================================
CREATE TABLE IF NOT EXISTS exam_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    completion_id UUID NOT NULL REFERENCES requirement_completions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requirement_id UUID NOT NULL REFERENCES curriculum_requirements(id) ON DELETE CASCADE,

    -- Submission type
    submission_type VARCHAR(20) NOT NULL CHECK (submission_type IN (
        'VIDEO', 'DOCUMENT', 'QUIZ', 'LIVE_SESSION'
    )),

    -- Video submission
    video_id UUID,  -- Link to videos table
    video_url VARCHAR(512),
    video_duration INTEGER,  -- seconds

    -- Skeleton data (for technique comparison)
    skeleton_data JSONB,  -- Extracted skeleton landmarks
    skeleton_file_url VARCHAR(512),

    -- AI Analysis results
    ai_analysis JSONB,
    ai_score INTEGER,
    ai_feedback TEXT,
    ai_suggestions JSONB,  -- Array of improvement suggestions

    -- Maestro Review
    maestro_id UUID REFERENCES maestros(id) ON DELETE SET NULL,
    maestro_score INTEGER,
    maestro_feedback TEXT,
    maestro_reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Final status
    final_score INTEGER,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'PROCESSING', 'AI_REVIEWED', 'MAESTRO_REVIEWED', 'APPROVED', 'REJECTED'
    )),

    -- Timestamps
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_exam_submissions_student_id ON exam_submissions(student_id);
CREATE INDEX idx_exam_submissions_status ON exam_submissions(status);
CREATE INDEX idx_exam_submissions_requirement_id ON exam_submissions(requirement_id);

-- =============================================================================
-- CERTIFICATES - Generated certificates for level completions
-- =============================================================================
CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    curriculum_id UUID NOT NULL REFERENCES curricula(id) ON DELETE CASCADE,
    level_id UUID NOT NULL REFERENCES curriculum_levels(id) ON DELETE CASCADE,
    progress_id UUID REFERENCES student_progress(id) ON DELETE SET NULL,

    -- Certificate info
    certificate_number VARCHAR(50) NOT NULL UNIQUE,  -- e.g., "CERT-2025-KARATE-00001"
    certificate_type VARCHAR(20) DEFAULT 'LEVEL' CHECK (certificate_type IN (
        'LEVEL', 'CURRICULUM_COMPLETION', 'SPECIAL_ACHIEVEMENT', 'INSTRUCTOR'
    )),

    -- Details
    student_name VARCHAR(255) NOT NULL,
    curriculum_name VARCHAR(255) NOT NULL,
    level_name VARCHAR(255) NOT NULL,
    martial_art VARCHAR(100) NOT NULL,

    -- Issuer
    issued_by_maestro_id UUID REFERENCES maestros(id) ON DELETE SET NULL,
    issued_by_asd_id UUID REFERENCES asds(id) ON DELETE SET NULL,
    issuer_name VARCHAR(255),

    -- PDF/Image
    pdf_url VARCHAR(512),
    image_url VARCHAR(512),

    -- Verification
    verification_code VARCHAR(100) NOT NULL UNIQUE,  -- For QR code verification
    blockchain_hash VARCHAR(256),  -- Optional blockchain registration

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason TEXT,

    -- Timestamps
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE,  -- NULL = never expires
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_certificates_student_id ON certificates(student_id);
CREATE INDEX idx_certificates_curriculum_id ON certificates(curriculum_id);
CREATE INDEX idx_certificates_verification_code ON certificates(verification_code);
CREATE INDEX idx_certificates_certificate_number ON certificates(certificate_number);

-- =============================================================================
-- INVITE_CODES - For private curriculum access
-- =============================================================================
CREATE TABLE IF NOT EXISTS invite_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    curriculum_id UUID NOT NULL REFERENCES curricula(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Code
    code VARCHAR(20) NOT NULL UNIQUE,  -- e.g., "KARATE-XYZ123"

    -- Limits
    max_uses INTEGER,  -- NULL = unlimited
    current_uses INTEGER DEFAULT 0,

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_invite_codes_code ON invite_codes(code);
CREATE INDEX idx_invite_codes_curriculum_id ON invite_codes(curriculum_id);

-- =============================================================================
-- INVITE_CODE_USAGES - Track who used which invite codes
-- =============================================================================
CREATE TABLE IF NOT EXISTS invite_code_usages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relationships
    invite_code_id UUID NOT NULL REFERENCES invite_codes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Timestamps
    used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT invite_code_usages_unique UNIQUE (invite_code_id, user_id)
);

CREATE INDEX idx_invite_code_usages_user_id ON invite_code_usages(user_id);

-- =============================================================================
-- Trigger: Update timestamp on modification
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to all curriculum tables
CREATE TRIGGER update_curricula_updated_at
    BEFORE UPDATE ON curricula
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_curriculum_levels_updated_at
    BEFORE UPDATE ON curriculum_levels
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_curriculum_requirements_updated_at
    BEFORE UPDATE ON curriculum_requirements
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_student_progress_updated_at
    BEFORE UPDATE ON student_progress
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_requirement_completions_updated_at
    BEFORE UPDATE ON requirement_completions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_exam_submissions_updated_at
    BEFORE UPDATE ON exam_submissions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Grant permissions (adjust as needed for your setup)
-- =============================================================================
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO martial_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO martial_user;

-- =============================================================================
-- End of migration
-- =============================================================================
