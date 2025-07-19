-- Tests for TOAST compression with zstd

SELECT NOT(enumvals @> '{zstd}') AS skip_test FROM pg_settings WHERE
  name = 'default_toast_compression' \gset
\if :skip_test
   \echo '*** skipping TOAST tests with zstd (not supported) ***'
   \quit
\endif

CREATE SCHEMA zstd;
SET search_path TO zstd, public;

\set HIDE_TOAST_COMPRESSION false

-- Ensure we get stable results regardless of the installation's default.
-- We rely on this GUC value for a few tests.
SET default_toast_compression = 'pglz';

-- test creating table with compression method
CREATE TABLE cmdata_pglz(f1 text COMPRESSION pglz);
CREATE INDEX idx ON cmdata_pglz(f1);
INSERT INTO cmdata_pglz VALUES(repeat('1234567890', 1000));
\d+ cmdata
CREATE TABLE cmdata_zstd(f1 TEXT COMPRESSION zstd);
INSERT INTO cmdata_zstd VALUES(repeat('1234567890', 1004));
\d+ cmdata1

-- verify stored compression method in the data
SELECT pg_column_compression(f1) FROM cmdata_zstd;

-- decompress data slice
SELECT SUBSTR(f1, 200, 5) FROM cmdata_pglz;
SELECT SUBSTR(f1, 2000, 50) FROM cmdata_zstd;

-- copy with table creation
SELECT * INTO cmmove1 FROM cmdata_zstd;
\d+ cmmove1
SELECT pg_column_compression(f1) FROM cmmove1;

-- test LIKE INCLUDING COMPRESSION.  The GUC default_toast_compression
-- has no effect, the compression method from the table being copied.
CREATE TABLE cmdata2 (LIKE cmdata_zstd INCLUDING COMPRESSION);
\d+ cmdata2
DROP TABLE cmdata2;

-- copy to existing table
CREATE TABLE cmmove3(f1 text COMPRESSION pglz);
INSERT INTO cmmove3 SELECT * FROM cmdata_pglz;
INSERT INTO cmmove3 SELECT * FROM cmdata_zstd;
SELECT pg_column_compression(f1) FROM cmmove3;

-- update using datum from different table with zstd data.
CREATE TABLE cmmove2(f1 text COMPRESSION pglz);
INSERT INTO cmmove2 VALUES (repeat('1234567890', 1004));
SELECT pg_column_compression(f1) FROM cmmove2;
UPDATE cmmove2 SET f1 = cmdata_zstd.f1 FROM cmdata_zstd;
SELECT pg_column_compression(f1) FROM cmmove2;

-- test externally stored compressed data
CREATE OR REPLACE FUNCTION large_val_zstd() RETURNS TEXT LANGUAGE SQL AS
'select array_agg(fipshash(g::text))::text from generate_series(1, 256) g';
CREATE TABLE cmdata2 (f1 text COMPRESSION zstd);
INSERT INTO cmdata2 SELECT large_val_zstd() || repeat('a', 4000);
SELECT pg_column_compression(f1) FROM cmdata2;
SELECT SUBSTR(f1, 200, 5) FROM cmdata2;
DROP TABLE cmdata2;
DROP FUNCTION large_val_zstd;

-- test compression with materialized view
CREATE MATERIALIZED VIEW compressmv(x) AS SELECT * FROM cmdata_zstd;
\d+ compressmv
SELECT pg_column_compression(f1) FROM cmdata_zstd;
SELECT pg_column_compression(x) FROM compressmv;

-- test compression with partition
CREATE TABLE cmpart(f1 text COMPRESSION zstd) PARTITION BY HASH(f1);
CREATE TABLE cmpart1 PARTITION OF cmpart FOR VALUES WITH (MODULUS 2, REMAINDER 0);
CREATE TABLE cmpart2(f1 text COMPRESSION pglz);

ALTER TABLE cmpart ATTACH PARTITION cmpart2 FOR VALUES WITH (MODULUS 2, REMAINDER 1);
INSERT INTO cmpart VALUES (repeat('123456789', 1004));
INSERT INTO cmpart VALUES (repeat('123456789', 4004));
SELECT pg_column_compression(f1) FROM cmpart1;
SELECT pg_column_compression(f1) FROM cmpart2;

-- test compression with inheritance
CREATE TABLE cminh() INHERITS(cmdata_pglz, cmdata_zstd); -- error
CREATE TABLE cminh(f1 TEXT COMPRESSION zstd) INHERITS(cmdata_pglz); -- error
CREATE TABLE cmdata3(f1 text);
CREATE TABLE cminh() INHERITS (cmdata_pglz, cmdata3);

-- test default_toast_compression GUC
SET default_toast_compression = 'zstd';

-- test alter compression method
ALTER TABLE cmdata_pglz ALTER COLUMN f1 SET COMPRESSION zstd;
INSERT INTO cmdata_pglz VALUES (repeat('123456789', 4004));
\d+ cmdata
SELECT pg_column_compression(f1) FROM cmdata_pglz;
ALTER TABLE cmdata_pglz ALTER COLUMN f1 SET COMPRESSION pglz;

-- test alter compression method for materialized views
ALTER MATERIALIZED VIEW compressmv ALTER COLUMN x SET COMPRESSION zstd;
\d+ compressmv

-- test alter compression method for partitioned tables
ALTER TABLE cmpart1 ALTER COLUMN f1 SET COMPRESSION pglz;
ALTER TABLE cmpart2 ALTER COLUMN f1 SET COMPRESSION zstd;

-- new data should be compressed with the current compression method
INSERT INTO cmpart VALUES (repeat('123456789', 1004));
INSERT INTO cmpart VALUES (repeat('123456789', 4004));
SELECT pg_column_compression(f1) FROM cmpart1;
SELECT pg_column_compression(f1) FROM cmpart2;

-- test expression index
CREATE TABLE cmdata2 (f1 TEXT COMPRESSION pglz, f2 TEXT COMPRESSION zstd);
CREATE UNIQUE INDEX idx1 ON cmdata2 ((f1 || f2));
INSERT INTO cmdata2 VALUES((SELECT array_agg(fipshash(g::TEXT))::TEXT FROM
generate_series(1, 50) g), VERSION());

-- check data is ok
SELECT length(f1) FROM cmdata_pglz;
SELECT length(f1) FROM cmdata_zstd;
SELECT length(f1) FROM cmmove1;
SELECT length(f1) FROM cmmove2;
SELECT length(f1) FROM cmmove3;

\set HIDE_TOAST_COMPRESSION true
