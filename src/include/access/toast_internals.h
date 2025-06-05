/*-------------------------------------------------------------------------
 *
 * toast_internals.h
 *	  Internal definitions for the TOAST system.
 *
 * Copyright (c) 2000-2025, PostgreSQL Global Development Group
 *
 * src/include/access/toast_internals.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_INTERNALS_H
#define TOAST_INTERNALS_H

#include "access/toast_compression.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"

/*
 * Utilities for manipulation of header information for compressed
 * toast entries.
 */
#define TOAST_COMPRESS_SET_SIZE_AND_COMPRESS_METHOD(ptr, len, cm_method)														\
	do {																														\
		Assert((len) > 0 && (len) <= VARLENA_EXTSIZE_MASK);																		\
		Assert((cm_method) == TOAST_PGLZ_COMPRESSION_ID ||																		\
				(cm_method) == TOAST_LZ4_COMPRESSION_ID ||																		\
				(cm_method) == TOAST_ZSTD_COMPRESSION_ID);																		\
		if (!TOAST_CMPID_EXTENDED((cm_method)))																					\
			((varattrib_4b *)(ptr))->va_compressed.va_tcinfo = ((uint32)(len)) | ((uint32)(cm_method) << VARLENA_EXTSIZE_BITS);	\
		else																													\
		{																														\
			/* extended path: mark EXT flag in tcinfo */																		\
			((varattrib_4b *)(ptr))->va_compressed_ext.va_tcinfo =																\
				((uint32)(len)) | ((uint32)(VARATT_4BCE_EXTFLAG) << VARLENA_EXTSIZE_BITS);										\
			VARATT_4BCE_SET_COMPRESS_METHOD(((varattrib_4b *)(ptr))->va_compressed_ext.va_ecinfo, (cm_method));					\
		}																														\
	} while (0)

extern Datum toast_compress_datum(Datum value, char cmethod);
extern Oid	toast_get_valid_index(Oid toastoid, LOCKMODE lock);

extern void toast_delete_datum(Relation rel, Datum value, bool is_speculative);
extern Datum toast_save_datum(Relation rel, Datum value,
							  struct varlena *oldexternal, int options);

extern int	toast_open_indexes(Relation toastrel,
							   LOCKMODE lock,
							   Relation **toastidxs,
							   int *num_indexes);
extern void toast_close_indexes(Relation *toastidxs, int num_indexes,
								LOCKMODE lock);
extern Snapshot get_toast_snapshot(void);

#endif							/* TOAST_INTERNALS_H */
