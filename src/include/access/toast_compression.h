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

/*
 * GUC support.
 *
 * default_toast_compression is an integer for purposes of the GUC machinery,
 * but the value is one of the char values defined below, as they appear in
 * pg_attribute.attcompression, e.g. TOAST_PGLZ_COMPRESSION.
 */
extern PGDLLIMPORT int default_toast_compression;

/*
 * Built-in compression method ID.
 *
 * For TOAST-compressed values:
 *   - If using a non-extended method, the first 2 bits of the raw length
 *     field store this ID.
 *   - If using an extended method, it is stored in the extended 1-byte header.
 *
 * For varlena attributes using extended compression (varatt_external and varattr_4b):
 *   - The compression method ID occupies the first seven bits of va_extinfo.
 *
 * These IDs map directly to the built-in compression methods.
 *
 * Note: Do not use these values for anything other than interpreting the
 * raw bits from a varlena. To identify a compression method in code, use
 * the named constants (e.g., TOAST_PGLZ_COMPRESSION) instead.
 */
typedef enum ToastCompressionId
{
	TOAST_PGLZ_COMPRESSION_ID = 0,
	TOAST_LZ4_COMPRESSION_ID = 1,
	TOAST_INVALID_COMPRESSION_ID = 2,
} ToastCompressionId;

/*
 * Built-in compression methods.  pg_attribute will store these in the
 * attcompression column.  In attcompression, InvalidCompressionMethod
 * denotes the default behavior.
 */
#define TOAST_PGLZ_COMPRESSION			'p'
#define TOAST_LZ4_COMPRESSION			'l'
#define InvalidCompressionMethod		'\0'

#define CompressionMethodIsValid(cm)  ((cm) != InvalidCompressionMethod)
#define TOAST_CMPID_EXTENDED(cmpid)	(!(cmpid == TOAST_PGLZ_COMPRESSION_ID ||	\
										cmpid == TOAST_LZ4_COMPRESSION_ID ||	\
										cmpid == TOAST_INVALID_COMPRESSION_ID))


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

#endif							/* TOAST_COMPRESSION_H */
