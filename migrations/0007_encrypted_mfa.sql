-- Existing plaintext must be sealed by the migrate command before readiness.
-- NOT VALID preserves existing values until the explicit transactional data cutover;
-- PostgreSQL nevertheless rejects new plaintext values immediately.
ALTER TABLE mfa_secrets ADD CONSTRAINT mfa_secret_encrypted
 CHECK (secret_key LIKE 'enc:%') NOT VALID;
