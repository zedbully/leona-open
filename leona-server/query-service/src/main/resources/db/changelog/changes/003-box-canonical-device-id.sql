-- Liquibase formatted SQL

-- changeset leona:0005-box-canonical-device-id
ALTER TABLE boxes
    ADD COLUMN IF NOT EXISTS canonical_device_id TEXT;

CREATE INDEX IF NOT EXISTS idx_boxes_canonical_device
    ON boxes (tenant_id, canonical_device_id)
    WHERE canonical_device_id IS NOT NULL;
