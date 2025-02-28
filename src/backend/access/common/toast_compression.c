/*-------------------------------------------------------------------------
 *
 * toast_compression.c
 *	  Functions for toast compression.
 *
 * Copyright (c) 2021-2025, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/common/toast_compression.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#ifdef USE_LZ4
#include <lz4.h>
#endif

#ifdef USE_ZSTD
#include <zstd.h>
#include <zdict.h>
#endif

#include "access/detoast.h"
#include "access/toast_compression.h"
#include "common/pg_lzcompress.h"
#include "varatt.h"
#include "catalog/pg_zstd_dictionaries.h"
#include "utils/syscache.h"
#include "access/htup_details.h"
#include "fmgr.h"

/* GUC */
int			default_toast_compression = TOAST_PGLZ_COMPRESSION;

#define NO_METHOD_SUPPORT(method) \
	ereport(ERROR, \
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED), \
			 errmsg("compression method %s not supported", method), \
			 errdetail("This functionality requires the server to be built with %s support.", method)))

/*
 * Compress a varlena using PGLZ.
 *
 * Returns the compressed varlena, or NULL if compression fails.
 */
struct varlena *
pglz_compress_datum(const struct varlena *value)
{
	int32		valsize,
				len;
	struct varlena *tmp = NULL;

	valsize = VARSIZE_ANY_EXHDR(value);

	/*
	 * No point in wasting a palloc cycle if value size is outside the allowed
	 * range for compression.
	 */
	if (valsize < PGLZ_strategy_default->min_input_size ||
		valsize > PGLZ_strategy_default->max_input_size)
		return NULL;

	/*
	 * Figure out the maximum possible size of the pglz output, add the bytes
	 * that will be needed for varlena overhead, and allocate that amount.
	 */
	tmp = (struct varlena *) palloc(PGLZ_MAX_OUTPUT(valsize) +
									VARHDRSZ_COMPRESSED);

	len = pglz_compress(VARDATA_ANY(value),
						valsize,
						(char *) tmp + VARHDRSZ_COMPRESSED,
						NULL);
	if (len < 0)
	{
		pfree(tmp);
		return NULL;
	}

	SET_VARSIZE_COMPRESSED(tmp, len + VARHDRSZ_COMPRESSED);

	return tmp;
}

/*
 * Decompress a varlena that was compressed using PGLZ.
 */
struct varlena *
pglz_decompress_datum(const struct varlena *value)
{
	struct varlena *result;
	int32		rawsize;

	/* allocate memory for the uncompressed data */
	result = (struct varlena *) palloc(VARDATA_COMPRESSED_GET_EXTSIZE(value) + VARHDRSZ);

	/* decompress the data */
	rawsize = pglz_decompress((char *) value + VARHDRSZ_COMPRESSED,
							  VARSIZE(value) - VARHDRSZ_COMPRESSED,
							  VARDATA(result),
							  VARDATA_COMPRESSED_GET_EXTSIZE(value), true);
	if (rawsize < 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("compressed pglz data is corrupt")));

	SET_VARSIZE(result, rawsize + VARHDRSZ);

	return result;
}

/*
 * Decompress part of a varlena that was compressed using PGLZ.
 */
struct varlena *
pglz_decompress_datum_slice(const struct varlena *value,
							int32 slicelength)
{
	struct varlena *result;
	int32		rawsize;

	/* allocate memory for the uncompressed data */
	result = (struct varlena *) palloc(slicelength + VARHDRSZ);

	/* decompress the data */
	rawsize = pglz_decompress((char *) value + VARHDRSZ_COMPRESSED,
							  VARSIZE(value) - VARHDRSZ_COMPRESSED,
							  VARDATA(result),
							  slicelength, false);
	if (rawsize < 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("compressed pglz data is corrupt")));

	SET_VARSIZE(result, rawsize + VARHDRSZ);

	return result;
}

/*
 * Compress a varlena using LZ4.
 *
 * Returns the compressed varlena, or NULL if compression fails.
 */
struct varlena *
lz4_compress_datum(const struct varlena *value)
{
#ifndef USE_LZ4
	NO_METHOD_SUPPORT("lz4");
	return NULL;				/* keep compiler quiet */
#else
	int32		valsize;
	int32		len;
	int32		max_size;
	struct varlena *tmp = NULL;

	valsize = VARSIZE_ANY_EXHDR(value);

	/*
	 * Figure out the maximum possible size of the LZ4 output, add the bytes
	 * that will be needed for varlena overhead, and allocate that amount.
	 */
	max_size = LZ4_compressBound(valsize);
	tmp = (struct varlena *) palloc(max_size + VARHDRSZ_COMPRESSED);

	len = LZ4_compress_default(VARDATA_ANY(value),
							   (char *) tmp + VARHDRSZ_COMPRESSED,
							   valsize, max_size);
	if (len <= 0)
		elog(ERROR, "lz4 compression failed");

	/* data is incompressible so just free the memory and return NULL */
	if (len > valsize)
	{
		pfree(tmp);
		return NULL;
	}

	SET_VARSIZE_COMPRESSED(tmp, len + VARHDRSZ_COMPRESSED);

	return tmp;
#endif
}

/*
 * Decompress a varlena that was compressed using LZ4.
 */
struct varlena *
lz4_decompress_datum(const struct varlena *value)
{
#ifndef USE_LZ4
	NO_METHOD_SUPPORT("lz4");
	return NULL;				/* keep compiler quiet */
#else
	int32		rawsize;
	struct varlena *result;

	/* allocate memory for the uncompressed data */
	result = (struct varlena *) palloc(VARDATA_COMPRESSED_GET_EXTSIZE(value) + VARHDRSZ);

	/* decompress the data */
	rawsize = LZ4_decompress_safe((char *) value + VARHDRSZ_COMPRESSED,
								  VARDATA(result),
								  VARSIZE(value) - VARHDRSZ_COMPRESSED,
								  VARDATA_COMPRESSED_GET_EXTSIZE(value));
	if (rawsize < 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("compressed lz4 data is corrupt")));


	SET_VARSIZE(result, rawsize + VARHDRSZ);

	return result;
#endif
}

/*
 * Decompress part of a varlena that was compressed using LZ4.
 */
struct varlena *
lz4_decompress_datum_slice(const struct varlena *value, int32 slicelength)
{
#ifndef USE_LZ4
	NO_METHOD_SUPPORT("lz4");
	return NULL;				/* keep compiler quiet */
#else
	int32		rawsize;
	struct varlena *result;

	/* slice decompression not supported prior to 1.8.3 */
	if (LZ4_versionNumber() < 10803)
		return lz4_decompress_datum(value);

	/* allocate memory for the uncompressed data */
	result = (struct varlena *) palloc(slicelength + VARHDRSZ);

	/* decompress the data */
	rawsize = LZ4_decompress_safe_partial((char *) value + VARHDRSZ_COMPRESSED,
										  VARDATA(result),
										  VARSIZE(value) - VARHDRSZ_COMPRESSED,
										  slicelength,
										  slicelength);
	if (rawsize < 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("compressed lz4 data is corrupt")));

	SET_VARSIZE(result, rawsize + VARHDRSZ);

	return result;
#endif
}

/*
 * Extract compression ID from a varlena.
 *
 * Returns TOAST_INVALID_COMPRESSION_ID if the varlena is not compressed.
 */
ToastCompressionId
toast_get_compression_id(struct varlena *attr)
{
	ToastCompressionId cmid = TOAST_INVALID_COMPRESSION_ID;

	/*
	 * If it is stored externally then fetch the compression method id from
	 * the external toast pointer.  If compressed inline, fetch it from the
	 * toast compression header.
	 */
	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		struct varatt_external toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
			cmid = VARATT_EXTERNAL_GET_COMPRESS_METHOD(toast_pointer);
	}
	else if (VARATT_IS_COMPRESSED(attr))
		cmid = VARDATA_COMPRESSED_GET_COMPRESS_METHOD(attr);

	return cmid;
}

/*
 * CompressionNameToMethod - Get compression method from compression name
 *
 * Search in the available built-in methods.  If the compression not found
 * in the built-in methods then return InvalidCompressionMethod.
 */
char
CompressionNameToMethod(const char *compression)
{
	if (strcmp(compression, "pglz") == 0)
		return TOAST_PGLZ_COMPRESSION;
	else if (strcmp(compression, "lz4") == 0)
	{
#ifndef USE_LZ4
		NO_METHOD_SUPPORT("lz4");
#endif
		return TOAST_LZ4_COMPRESSION;
	}
	else if (strcmp(compression, "zstd") == 0)
	{
#ifndef USE_ZSTD
		NO_METHOD_SUPPORT("zstd");
#endif
		return TOAST_ZSTD_COMPRESSION;
	}

	return InvalidCompressionMethod;
}

/*
 * GetCompressionMethodName - Get compression method name
 */
const char *
GetCompressionMethodName(char method)
{
	switch (method)
	{
		case TOAST_PGLZ_COMPRESSION:
			return "pglz";
		case TOAST_LZ4_COMPRESSION:
			return "lz4";
		case TOAST_ZSTD_COMPRESSION:
			return "zstd";
		default:
			elog(ERROR, "invalid compression method %c", method);
			return NULL;		/* keep compiler quiet */
	}
}

/* Compress datum using ZSTD with optional dictionary (using cdict) */
struct varlena *
zstd_compress_datum(const struct varlena *value, Oid dictid, int zstd_level)
{
#ifdef USE_ZSTD
	uint32		valsize = VARSIZE_ANY_EXHDR(value);
	size_t		max_size = ZSTD_compressBound(valsize);
	struct varlena *compressed;
	void	   *dest;
	size_t		cmp_size,
				ret;
	ZSTD_CCtx  *cctx = ZSTD_createCCtx();
	ZSTD_CDict *cdict = NULL;

	if (!cctx)
		ereport(ERROR, (errmsg("Failed to create ZSTD compression context")));

	/* Allocate space for the compressed varlena (header + data) */
	compressed = (struct varlena *) palloc(max_size + VARHDRSZ_COMPRESSED_EXT);
	dest = (char *) compressed + VARHDRSZ_COMPRESSED_EXT;

	if (dictid != InvalidDictId)
	{
		bytea	   *dict_bytea = get_zstd_dict_bytea(dictid);
		const void *dict_buffer = VARDATA_ANY(dict_bytea);
		uint32		dict_size = VARSIZE_ANY(dict_bytea) - VARHDRSZ;

		cdict = ZSTD_createCDict(dict_buffer, dict_size, zstd_level);
		ret = ZSTD_CCtx_refCDict(cctx, cdict);
		if (ZSTD_isError(ret))
			ereport(ERROR, (errmsg("Failed to reference ZSTD dictionary")));
		pfree(dict_bytea);
	}

	/* Compress the data */
	cmp_size = ZSTD_compress2(cctx, dest, max_size, VARDATA_ANY(value), valsize);

	if (ZSTD_isError(cmp_size))
		ereport(ERROR, (errmsg("ZSTD compression failed: %s", ZSTD_getErrorName(cmp_size))));

	/* Cleanup */
	ZSTD_freeCDict(cdict);
	ZSTD_freeCCtx(cctx);

	/*
	 * If compression did not reduce size, return NULL so that the
	 * uncompressed data is stored
	 */
	if (cmp_size > valsize)
	{
		pfree(compressed);
		return NULL;
	}

	/* Set the compressed size in the varlena header */
	SET_VARSIZE_COMPRESSED(compressed, cmp_size + VARHDRSZ_COMPRESSED_EXT);
	return compressed;

#else
	NO_METHOD_SUPPORT("zstd");
	return NULL;
#endif
}

struct varlena *
zstd_decompress_datum(const struct varlena *value)
{
#ifdef USE_ZSTD
	uint32		actual_size_exhdr = VARDATA_COMPRESSED_GET_EXTSIZE(value);
	uint32		cmp_size_exhdr = VARSIZE_4B(value) - VARHDRSZ_COMPRESSED_EXT;
	Oid			dictid;
	struct varlena *result;
	size_t		uncmp_size,
				ret;
	ZSTD_DCtx  *dctx = ZSTD_createDCtx();
	ZSTD_DDict *ddict = NULL;

	if (!dctx)
		ereport(ERROR, (errmsg("Failed to create ZSTD decompression context")));

	/*
	 * Extract the dictionary ID from the compressed frame. This function
	 * reads the dictionary ID from the frame header.
	 */
	dictid = (Oid) ZSTD_getDictID_fromFrame(VARDATA_4B_C(value), cmp_size_exhdr);

	/* Allocate space for the uncompressed data */
	result = (struct varlena *) palloc(actual_size_exhdr + VARHDRSZ);

	if (dictid != InvalidDictId)
	{
		bytea	   *dict_bytea = get_zstd_dict_bytea(dictid);
		const void *dict_buffer = VARDATA_ANY(dict_bytea);
		uint32		dict_size = VARSIZE_ANY(dict_bytea) - VARHDRSZ;

		ddict = ZSTD_createDDict(dict_buffer, dict_size);
		ret = ZSTD_DCtx_refDDict(dctx, ddict);
		if (ZSTD_isError(ret))
			ereport(ERROR, (errmsg("Failed to reference ZSTD dictionary")));
		pfree(dict_bytea);
	}

	uncmp_size = ZSTD_decompressDCtx(dctx,
									 VARDATA(result),
									 actual_size_exhdr,
									 VARDATA_4B_C(value),
									 cmp_size_exhdr);

	if (ZSTD_isError(uncmp_size))
		ereport(ERROR, (errmsg("ZSTD decompression failed: %s", ZSTD_getErrorName(uncmp_size))));

	/* Cleanup */
	ZSTD_freeDDict(ddict);
	ZSTD_freeDCtx(dctx);

	/* Set final size in the varlena header */
	SET_VARSIZE(result, uncmp_size + VARHDRSZ);
	return result;

#else
	NO_METHOD_SUPPORT("zstd");
	return NULL;
#endif
}

/* Decompress a slice of the datum using the streaming API and optional dictionary */
struct varlena *
zstd_decompress_datum_slice(const struct varlena *value, int32 slicelength)
{
#ifdef USE_ZSTD
	struct varlena *result;
	ZSTD_inBuffer inBuf;
	ZSTD_outBuffer outBuf;
	ZSTD_DCtx  *dctx = ZSTD_createDCtx();
	ZSTD_DDict *ddict = NULL;
	Oid			dictid;
	uint32		cmp_size_exhdr = VARSIZE_4B(value) - VARHDRSZ_COMPRESSED_EXT;
	size_t		ret;

	if (dctx == NULL)
		elog(ERROR, "could not create zstd decompression context");

	/* Extract the dictionary ID from the compressed frame */
	dictid = (Oid) ZSTD_getDictID_fromFrame(VARDATA_4B_C(value), cmp_size_exhdr);

	inBuf.src = (char *) value + VARHDRSZ_COMPRESSED_EXT;
	inBuf.size = VARSIZE(value) - VARHDRSZ_COMPRESSED_EXT;
	inBuf.pos = 0;

	result = (struct varlena *) palloc(slicelength + VARHDRSZ);
	outBuf.dst = (char *) result + VARHDRSZ;
	outBuf.size = slicelength;
	outBuf.pos = 0;

	if (dictid != InvalidDictId)
	{
		bytea	   *dict_bytea = get_zstd_dict_bytea(dictid);
		const void *dict_buffer = VARDATA_ANY(dict_bytea);
		uint32		dict_size = VARSIZE_ANY(dict_bytea) - VARHDRSZ;

		/* Create and bind the dictionary to the decompression context */
		ddict = ZSTD_createDDict(dict_buffer, dict_size);
		ret = ZSTD_DCtx_refDDict(dctx, ddict);
		if (ZSTD_isError(ret))
			elog(ERROR, "could not reference zstd dictionary: %s", ZSTD_getErrorName(ret));
		pfree(dict_bytea);
	}

	/* Common decompression loop */
	while (inBuf.pos < inBuf.size && outBuf.pos < outBuf.size)
	{
		ret = ZSTD_decompressStream(dctx, &outBuf, &inBuf);
		if (ZSTD_isError(ret))
			elog(ERROR, "zstd decompression failed: %s", ZSTD_getErrorName(ret));
	}

	/* Cleanup */
	ZSTD_freeDDict(ddict);
	ZSTD_freeDCtx(dctx);

	Assert(outBuf.size == slicelength && outBuf.pos == slicelength);
	SET_VARSIZE(result, outBuf.pos + VARHDRSZ);
	return result;
#else
	NO_METHOD_SUPPORT("zstd");
	return NULL;
#endif
}
