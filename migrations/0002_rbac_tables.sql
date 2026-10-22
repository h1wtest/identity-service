-- =============================================================
-- Permissions table
-- =============================================================
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY,
    slug VARCHAR(100) NOT NULL UNIQUE,
    module VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_permissions_slug ON permissions (slug);
CREATE INDEX IF NOT EXISTS idx_permissions_module ON permissions (module);

-- =============================================================
-- Roles table
-- =============================================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    slug VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_roles_slug ON roles (slug);

-- =============================================================
-- Role Permissions (Many-to-Many)
-- =============================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- =============================================================
-- User Roles (User-to-Role assignment with optional expiry)
-- =============================================================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id);

-- =============================================================
-- Seed Initial Roles and Permissions
-- =============================================================

-- 1. Insert Core Roles
INSERT INTO roles (id, slug, name, description) VALUES
    ('018f0000-0000-7000-8000-000000000001', 'super_admin', 'Super Administrator', 'Full unrestricted platform access'),
    ('018f0000-0000-7000-8000-000000000002', 'admin', 'Administrator', 'Administrative access excluding root destructive operations'),
    ('018f0000-0000-7000-8000-000000000003', 'support', 'Support Staff', 'User assistance and session moderation'),
    ('018f0000-0000-7000-8000-000000000004', 'user', 'Regular User', 'Standard user permissions for profile and self sessions')
ON CONFLICT (slug) DO NOTHING;

-- 2. Insert Core Permissions
INSERT INTO permissions (id, slug, module, description) VALUES
    ('018f0000-0001-7000-8000-000000000001', 'users:self:read', 'users', 'Read own user profile and settings'),
    ('018f0000-0001-7000-8000-000000000002', 'users:self:update', 'users', 'Update own user profile and settings'),
    ('018f0000-0001-7000-8000-000000000003', 'users:sessions:self:read', 'users', 'View own active sessions'),
    ('018f0000-0001-7000-8000-000000000004', 'users:sessions:self:revoke', 'users', 'Revoke own active sessions'),
    ('018f0000-0001-7000-8000-000000000005', 'users:read', 'admin', 'View any user details in admin'),
    ('018f0000-0001-7000-8000-000000000006', 'users:ban', 'admin', 'Ban or unban user accounts'),
    ('018f0000-0001-7000-8000-000000000007', 'users:sessions:revoke', 'admin', 'Force revoke any user session'),
    ('018f0000-0001-7000-8000-000000000008', 'system:audit:read', 'admin', 'View immutable audit log'),
    ('018f0000-0001-7000-8000-000000000009', 'aws:ec2:reboot', 'aws', 'Trigger AWS EC2 restart command'),
    ('018f0000-0001-7000-8000-000000000010', 'aws:s3:read', 'aws', 'Inspect S3 storage buckets'),
    ('018f0000-0001-7000-8000-000000000011', 'news:articles:read', 'news', 'Read platform news and announcements'),
    ('018f0000-0001-7000-8000-000000000012', 'news:articles:publish', 'news', 'Create and publish news articles'),
    ('018f0000-0001-7000-8000-000000000013', 'feedback:bugs:create', 'feedback', 'Submit bug reports and feature requests'),
    ('018f0000-0001-7000-8000-000000000014', 'feedback:bugs:moderate', 'feedback', 'Change status of bug reports and proposals')
ON CONFLICT (slug) DO NOTHING;

-- 3. Link Regular User Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.slug = 'user' AND p.slug IN (
    'users:self:read',
    'users:self:update',
    'users:sessions:self:read',
    'users:sessions:self:revoke',
    'news:articles:read',
    'feedback:bugs:create'
)
ON CONFLICT DO NOTHING;

-- 4. Link Support Staff Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.slug = 'support' AND p.slug IN (
    'users:self:read',
    'users:self:update',
    'users:sessions:self:read',
    'users:sessions:self:revoke',
    'users:read',
    'users:sessions:revoke',
    'feedback:bugs:moderate',
    'news:articles:read'
)
ON CONFLICT DO NOTHING;

-- 5. Link Admin Permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.slug = 'admin' AND p.slug IN (
    'users:self:read',
    'users:self:update',
    'users:sessions:self:read',
    'users:sessions:self:revoke',
    'users:read',
    'users:ban',
    'users:sessions:revoke',
    'system:audit:read',
    'feedback:bugs:moderate',
    'news:articles:read',
    'news:articles:publish'
)
ON CONFLICT DO NOTHING;

-- 6. Link Super Admin (All Permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.slug = 'super_admin'
ON CONFLICT DO NOTHING;
