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
#endif

#include "access/detoast.h"
#include "access/toast_compression.h"
#include "common/pg_lzcompress.h"
#include "varatt.h"
#include "utils/attoptcache.h"

/* GUC */
int			default_toast_compression = TOAST_PGLZ_COMPRESSION;

#ifdef USE_ZSTD
#define ZSTD_CHECK_ERROR(zstd_ret, msg) \
	do { \
		if (ZSTD_isError(zstd_ret)) \
			ereport(ERROR, (errmsg("%s: %s", (msg), ZSTD_getErrorName(zstd_ret)))); \
	} while (0)
#endif

#define COMPRESSION_METHOD_NOT_SUPPORTED(method) \
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
	COMPRESSION_METHOD_NOT_SUPPORTED("lz4");
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
	COMPRESSION_METHOD_NOT_SUPPORTED("lz4");
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
	COMPRESSION_METHOD_NOT_SUPPORTED("lz4");
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

/* Compress datum using ZSTD with optional dictionary (using cdict) */
struct varlena *
zstd_nodict_compress_datum(const struct varlena *value, CompressionInfo cmp)
{
#ifdef USE_ZSTD
	uint32		valsize = VARSIZE_ANY_EXHDR(value);
	size_t		max_size = ZSTD_compressBound(valsize);
	struct varlena *compressed;
	size_t		cmp_size;

	/* Allocate space for the compressed varlena (header + data) */
	compressed = (struct varlena *) palloc(max_size + VARHDRSZ_4BCE);

	cmp_size = ZSTD_compress(VARDATA_4BCE(compressed),
							 max_size,
							 VARDATA_ANY(value),
							 valsize,
							 cmp.zstd_level);

	if (ZSTD_isError(cmp_size))
	{
		pfree(compressed);
		ZSTD_CHECK_ERROR(cmp_size, "ZSTD compression failed");
	}

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
	SET_VARSIZE_COMPRESSED(compressed, cmp_size + VARHDRSZ_4BCE);
	return compressed;

#else
	COMPRESSION_METHOD_NOT_SUPPORTED("zstd_nodict");
	return NULL;
#endif
}

/* Decompression routine */
struct varlena *
zstd_nodict_decompress_datum(const struct varlena *value)
{
#ifdef USE_ZSTD
	uint32		actual_size_exhdr = VARDATA_COMPRESSED_GET_EXTSIZE(value);
	uint32		zstd_compressed_len = VARSIZE_ANY(value) - VARHDRSZ_4BCE;
	struct varlena *result;
	size_t		uncmp_size;

	/* Allocate space for the uncompressed data */
	result = (struct varlena *) palloc(actual_size_exhdr + VARHDRSZ);

	uncmp_size = ZSTD_decompress(VARDATA(result),
								 actual_size_exhdr,
								 VARDATA_4BCE(value),
								 zstd_compressed_len);

	if (ZSTD_isError(uncmp_size))
	{
		pfree(result);
		ZSTD_CHECK_ERROR(uncmp_size, "ZSTD decompression failed");
	}

	/* Set final size in the varlena header */
	SET_VARSIZE(result, uncmp_size + VARHDRSZ);
	return result;

#else
	COMPRESSION_METHOD_NOT_SUPPORTED("zstd_nodict");
	return NULL;
#endif
}

/* Decompress a slice of the datum using the streaming API and optional dictionary */
struct varlena *
zstd_nodict_decompress_datum_slice(const struct varlena *value, int32 slicelength)
{
#ifdef USE_ZSTD
	struct varlena *result;
	ZSTD_inBuffer inBuf;
	ZSTD_outBuffer outBuf;
	size_t		ret;
	ZSTD_DCtx  *ZstdDecompressionCtx = ZSTD_createDCtx();

	inBuf.src = VARDATA_4BCE(value);
	inBuf.size = VARSIZE_ANY(value) - VARHDRSZ_4BCE;
	inBuf.pos = 0;

	result = (struct varlena *) palloc(slicelength + VARHDRSZ);
	outBuf.dst = (char *) result + VARHDRSZ;
	outBuf.size = slicelength;
	outBuf.pos = 0;

	/* Common decompression loop */
	while (inBuf.pos < inBuf.size && outBuf.pos < outBuf.size)
	{
		ret = ZSTD_decompressStream(ZstdDecompressionCtx, &outBuf, &inBuf);
		if (ZSTD_isError(ret))
		{
			pfree(result);
			ZSTD_freeDCtx(ZstdDecompressionCtx);
			ZSTD_CHECK_ERROR(ret, "zstd decompression failed");
		}
	}

	Assert(outBuf.size == slicelength && outBuf.pos == slicelength);
	SET_VARSIZE(result, outBuf.pos + VARHDRSZ);
	ZSTD_freeDCtx(ZstdDecompressionCtx);
	return result;
#else
	COMPRESSION_METHOD_NOT_SUPPORTED("zstd_nodict");
	return NULL;
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
			cmid = VARATT_EXTERNAL_GET_COMPRESS_METHOD(&toast_pointer);
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
		COMPRESSION_METHOD_NOT_SUPPORTED("lz4");
#endif
		return TOAST_LZ4_COMPRESSION;
	}
	else if (strcmp(compression, "zstd_nodict") == 0)
	{
#ifndef USE_ZSTD
		COMPRESSION_METHOD_NOT_SUPPORTED("zstd_nodict");
#endif
		return TOAST_ZSTD_NODICT_COMPRESSION;
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
		case TOAST_ZSTD_NODICT_COMPRESSION:
			return "zstd_nodict";
		default:
			elog(ERROR, "invalid compression method %c", method);
			return NULL;		/* keep compiler quiet */
	}
}

CompressionInfo
setup_cmp_info(char cmethod, Form_pg_attribute att)
{
	CompressionInfo info;

	/* initialize from the attribute’s default settings */
	info.cmethod = cmethod;
	info.zstd_level = DEFAULT_ZSTD_LEVEL;

	/* If the compression method is not valid, use the current default */
	if (!CompressionMethodIsValid(cmethod))
		info.cmethod = default_toast_compression;

	switch (info.cmethod)
	{
		case TOAST_PGLZ_COMPRESSION:
		case TOAST_LZ4_COMPRESSION:
			break;
		case TOAST_ZSTD_NODICT_COMPRESSION:
			{
				AttributeOpts *aopt = get_attribute_options(att->attrelid, att->attnum);

				if (aopt != NULL)
					info.zstd_level = aopt->zstd_level;
			}
			break;
		default:
			elog(ERROR, "invalid compression method %c", info.cmethod);
	}

	return info;
}
