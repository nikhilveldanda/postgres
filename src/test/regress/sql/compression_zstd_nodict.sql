\set HIDE_TOAST_COMPRESSION false

-- Ensure stable results regardless of the installation's default.
SET default_toast_compression = 'pglz';

----------------------------------------------------------------
-- 1. Create Test Table with Zstd Compression
----------------------------------------------------------------
DROP TABLE IF EXISTS cmdata_zstd_nodict CASCADE;
CREATE TABLE cmdata_zstd_nodict (
    f1 TEXT COMPRESSION zstd_nodict
);

----------------------------------------------------------------
-- 2. Insert Data Rows
----------------------------------------------------------------
DO $$
BEGIN
  FOR i IN 1..15 LOOP
    INSERT INTO cmdata_zstd_nodict (f1) VALUES (repeat('1234567890', 1004)); -- inline
    INSERT INTO cmdata_zstd_nodict (f1) VALUES (repeat('1234567890', 2500000)); -- externally stored
  END LOOP;
END $$;

----------------------------------------------------------------
-- 3. Verify Table Structure and Compression Settings
----------------------------------------------------------------
-- Table Structure for cmdata_zstd
\d+ cmdata_zstd_nodict;

-- Compression Settings for f1 Column
SELECT pg_column_compression(f1) AS compression_method,
       count(*) AS row_count
FROM cmdata_zstd_nodict
GROUP BY pg_column_compression(f1);

----------------------------------------------------------------
-- 4. Decompression Tests
----------------------------------------------------------------
--  Decompression Slice Test (Extracting Substrings)
SELECT SUBSTR(f1, 200, 50) AS data_slice
FROM cmdata_zstd_nodict;

----------------------------------------------------------------
-- 5. Test Table Creation with LIKE INCLUDING COMPRESSION
----------------------------------------------------------------
DROP TABLE IF EXISTS cmdata_zstd_nodict_2;
CREATE TABLE cmdata_zstd_nodict_2 (LIKE cmdata_zstd_nodict INCLUDING COMPRESSION);
--  Table Structure for cmdata_zstd_2
\d+ cmdata_zstd_nodict_2;
DROP TABLE cmdata_zstd_nodict_2;

----------------------------------------------------------------
-- 6. Materialized View Compression Test
----------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS compressmv_zstd_nodict;
CREATE MATERIALIZED VIEW compressmv_zstd_nodict AS
  SELECT f1 FROM cmdata_zstd_nodict;

--  Materialized View Structure for compressmv_zstd
\d+ compressmv_zstd_nodict;

--  Materialized View Compression Check
SELECT pg_column_compression(f1) AS mv_compression
FROM compressmv_zstd_nodict;

----------------------------------------------------------------
-- 7. Additional Updates and Round-Trip Tests
----------------------------------------------------------------
-- Update some rows to check if the dictionary remains effective after modifications.
UPDATE cmdata_zstd_nodict
SET f1 = f1 || ' UPDATED';

--  Verification of Updated Rows
SELECT SUBSTR(f1, LENGTH(f1) - 7 + 1, 7) AS preview
FROM cmdata_zstd_nodict;
----------------------------------------------------------------
-- 8. Clean Up
----------------------------------------------------------------
DROP MATERIALIZED VIEW compressmv_zstd_nodict;
DROP TABLE cmdata_zstd_nodict;

\set HIDE_TOAST_COMPRESSION true
