/*-------------------------------------------------------------------------
 *
 * pg_zstd_dictionaries.h
 *	  definition of the "zstd dictionary" system catalog (pg_zstd_dictionaries)
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 * src/include/catalog/pg_zstd_dictionaries.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_ZSTD_DICTIONARIES_H
#define PG_ZSTD_DICTIONARIES_H

#include "catalog/genbki.h"
#include "catalog/pg_zstd_dictionaries_d.h"

/* ----------------
 *		pg_zstd_dictionaries definition.  cpp turns this into
 *		typedef struct FormData_pg_zstd_dictionaries
 * ----------------
 */
CATALOG(pg_zstd_dictionaries,9946,ZstdDictionariesRelationId)
{
	Oid			relid;
	int16		attnum;
	Oid			dictid;

	/*
	 * variable-length fields start here, but we allow direct access to dict
	 */
	bytea		dict BKI_FORCE_NOT_NULL;
} FormData_pg_zstd_dictionaries;

/* Pointer type to a tuple with the format of pg_zstd_dictionaries relation */
typedef FormData_pg_zstd_dictionaries *Form_pg_zstd_dictionaries;

DECLARE_TOAST_WITH_MACRO(pg_zstd_dictionaries, 9947, 9948, PgZstdDictionariesToastTable, PgZstdDictionariesToastIndex);

DECLARE_INDEX(pg_zstd_dictionaries_relid_attnum_index, 9949, ZstdRelidAttnumIndexId, pg_zstd_dictionaries, btree(relid oid_ops, attnum int2_ops));
DECLARE_UNIQUE_INDEX_PKEY(pg_zstd_dictionaries_dictid_index, 9950, ZstdDictidIndexId, pg_zstd_dictionaries, btree(dictid oid_ops));

MAKE_SYSCACHE(ZSTDDICTIDOID, pg_zstd_dictionaries_dictid_index, 128);

extern bytea *get_zstd_dict(Oid dictid);
extern void generate_zstd_dictionaries_for_relation(Oid relid);

#endif							/* PG_ZSTD_DICTIONARIES_H */
