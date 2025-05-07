/*-------------------------------------------------------------------------
 *
 * toast_compression.h
 *	  Functions for toast compression.
 *
 * Copyright (c) 2021-2025, PostgreSQL Global Development Group
 *
 * src/include/access/toast_compression.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef TOAST_COMPRESSION_H
#define TOAST_COMPRESSION_H

#include "varatt.h"
#include "catalog/pg_attribute.h"

/*
 * GUC support.
 *
 * default_toast_compression is an integer for purposes of the GUC machinery,
 * but the value is one of the char values defined below, as they appear in
 * pg_attribute.attcompression, e.g. TOAST_PGLZ_COMPRESSION.
 */
extern PGDLLIMPORT int default_toast_compression;

typedef enum ToastCompressionId
{
	TOAST_PGLZ_COMPRESSION_ID = 0,
	TOAST_LZ4_COMPRESSION_ID = 1,
	TOAST_INVALID_COMPRESSION_ID = 2,
} ToastCompressionId;

/*
 * toast_cmpid_extended
 *
 * Returns true if the given compression ID uses the extended on-disk format.
 */
static inline bool
toast_cmpid_extended(ToastCompressionId cmpid)
{
	/*
	 * only PGLZ, LZ4 are not extended; everything else uses extended on-disk
	 * format.
	 */
	return !(cmpid == TOAST_PGLZ_COMPRESSION_ID ||
			 cmpid == TOAST_LZ4_COMPRESSION_ID ||
			 cmpid == TOAST_INVALID_COMPRESSION_ID);
}

#define TOAST_CMPID_EXTENDED(alg)	(toast_cmpid_extended(alg))

typedef struct CompressionInfo
{
	char		cmethod;
} CompressionInfo;

/*
 * Built-in compression methods.  pg_attribute will store these in the
 * attcompression column.  In attcompression, InvalidCompressionMethod
 * denotes the default behavior.
 */
#define TOAST_PGLZ_COMPRESSION			'p'
#define TOAST_LZ4_COMPRESSION			'l'
#define InvalidCompressionMethod		'\0'

#define CompressionMethodIsValid(cm)  ((cm) != InvalidCompressionMethod)


/* pglz compression/decompression routines */
extern struct varlena *pglz_compress_datum(const struct varlena *value);
extern struct varlena *pglz_decompress_datum(const struct varlena *value);
extern struct varlena *pglz_decompress_datum_slice(const struct varlena *value,
												   int32 slicelength);

/* lz4 compression/decompression routines */
extern struct varlena *lz4_compress_datum(const struct varlena *value);
extern struct varlena *lz4_decompress_datum(const struct varlena *value);
extern struct varlena *lz4_decompress_datum_slice(const struct varlena *value,
												  int32 slicelength);

/* other stuff */
extern ToastCompressionId toast_get_compression_id(struct varlena *attr);
extern char CompressionNameToMethod(const char *compression);
extern const char *GetCompressionMethodName(char method);
extern CompressionInfo setup_cmp_info(char cmethod, Form_pg_attribute att);

#endif							/* TOAST_COMPRESSION_H */
