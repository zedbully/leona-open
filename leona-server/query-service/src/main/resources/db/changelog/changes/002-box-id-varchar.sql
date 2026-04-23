-- Liquibase formatted SQL

-- changeset leona:0004-box-id-varchar
ALTER TABLE boxes
    ALTER COLUMN box_id TYPE VARCHAR(26);
