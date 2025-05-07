/*-------------------------------------------------------------------------
 *
 * pg_zstd_dictionaries.c
 *	  routines to support manipulation of the pg_zstd_dictionaries relation
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/catalog/pg_zstd_dictionaries.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "fmgr.h"
#include "access/table.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_class_d.h"
#include "catalog/pg_zstd_dictionaries.h"
#include "catalog/pg_zstd_dictionaries_d.h"
#include "catalog/pg_depend.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "utils/attoptcache.h"
#include "parser/analyze.h"
#include "nodes/makefuncs.h"
#include "access/reloptions.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/sdir.h"
#include "utils/lsyscache.h"
#include "utils/relcache.h"
#include "utils/memutils.h"
#include "utils/varlena.h"
#include "nodes/pg_list.h"
#include "utils/array.h"
#include "utils/rangetypes.h"
#include "utils/multirangetypes.h"
#include "utils/snapmgr.h"
#include "access/xact.h"

#ifdef USE_ZSTD
#include <zstd.h>
#include <zdict.h>
#endif

#define TARGET_ROWS 30000

typedef struct ZstdTrainingData ZstdTrainingData;

struct ZstdTrainingData
{
	char	   *sample_buffer;	/* Pointer to the raw sample buffer */
	size_t	   *sample_sizes;	/* Array of sample sizes */
	size_t		nitems;			/* Number of sample sizes */
	size_t		total_size;		/* Running total sample size */
};

static bool build_zstd_dictionary_internal(Oid relid, AttrNumber attno);
static Oid	GetNewDictId(Relation relation);
static bool append_sample(ZstdTrainingData *dict, const char *sample, size_t sample_size);
static bool sample_varlena_datum(Datum datum, ZstdTrainingData *dict);

/*
 * build_zstd_dictionary_internal
 *   1) Validate that the given (relid, attno) can have a Zstd compression enabled on heap relation
 *   2) Call the type-specific sampling procedure
 *   3) Train a dictionary via ZDICT_trainFromBuffer()
 *   4) Insert dictionary into pg_zstd_dictionaries
 *   5) Update pg_attribute.attoptions with new zstd_dictid
 */
pg_attribute_unused()
static bool
build_zstd_dictionary_internal(Oid relid, AttrNumber attno)
{
#ifndef USE_ZSTD
	return false;
#else
	Relation	rel;
	Form_pg_attribute att;
	AttributeOpts *attopt;
	TypeCacheEntry *typentry;
	ZstdTrainingData dict = {0};
	HeapTuple	sample_rows[TARGET_ROWS];
	int			num_sampled;
	double		totalrows = 0,
				totaldeadrows = 0;
	int			i;
	size_t		dict_size;
	void	   *dict_data;
	Oid			zstd_dictid;
	bytea	   *dict_bytea;
	Relation	catalogRel,
				attRel;
	HeapTuple	tup,
				atttup,
				newtuple;
	Datum		values[Natts_pg_zstd_dictionaries];
	bool		nulls[Natts_pg_zstd_dictionaries];
	Datum		attoptionsDatum,
				newOptions;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	DefElem    *def;
	ObjectAddress dictObj,
				relObj;

	/* Open relation, verify regular table */
	rel = table_open(relid, AccessShareLock);
	if (rel->rd_rel->relkind != RELKIND_RELATION)
		goto fail;

	att = TupleDescAttr(RelationGetDescr(rel), attno - 1);
	if (att->attcompression != TOAST_ZSTD_DICT_COMPRESSION)
		goto fail;

	/* Check attoptions for user-requested dictionary size, etc. */
	attopt = get_attribute_options(relid, attno);
	if (attopt && attopt->zstd_dict_size == 0)
		goto fail;

	/*
	 * 2) Look up the type's custom dictionary builder function We'll call it
	 * to get sample training data.
	 */
	typentry = lookup_type_cache(att->atttypid, 0);
	if (typentry->typlen != -1 || !OidIsValid(typentry->typzstdsampling))
		goto fail;

	num_sampled = acquire_sample_rows(rel, 0, sample_rows, TARGET_ROWS, &totalrows, &totaldeadrows);
	if (num_sampled == 0)
		goto fail;

	for (i = 0; i < num_sampled; i++)
	{
		Datum		value;

		value = heap_getattr(sample_rows[i], attno, RelationGetDescr(rel), &isnull);

		if (!isnull && !DatumGetBool(OidFunctionCall2(typentry->typzstdsampling, value, PointerGetDatum(&dict))))
			break;
	}

	if (dict.nitems == 0)
		goto fail;

	/* ZSTD Dictionary training */
	dict_size = attopt ? attopt->zstd_dict_size : DEFAULT_ZSTD_DICT_SIZE;
	dict_data = palloc(dict_size);

	dict_size = ZDICT_trainFromBuffer(dict_data, dict_size, dict.sample_buffer, dict.sample_sizes, dict.nitems);
	if (ZDICT_isError(dict_size))
	{
		elog(LOG, "Zstd dictionary training failed: %s", ZDICT_getErrorName(dict_size));
		goto cleanup_dict;
	}

	/* Insert dictionary into catalog */
	dict_bytea = palloc(VARHDRSZ + dict_size);
	SET_VARSIZE(dict_bytea, VARHDRSZ + dict_size);
	memcpy(VARDATA(dict_bytea), dict_data, dict_size);

	catalogRel = table_open(ZstdDictionariesRelationId, ShareRowExclusiveLock);
	zstd_dictid = GetNewDictId(catalogRel);

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));
	values[Anum_pg_zstd_dictionaries_relid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_zstd_dictionaries_attnum - 1] = ObjectIdGetDatum(attno);
	values[Anum_pg_zstd_dictionaries_dictid - 1] = ObjectIdGetDatum(zstd_dictid);
	values[Anum_pg_zstd_dictionaries_dict - 1] = PointerGetDatum(dict_bytea);

	tup = heap_form_tuple(RelationGetDescr(catalogRel), values, nulls);
	CatalogTupleInsert(catalogRel, tup);

	heap_freetuple(tup);
	pfree(dict_bytea);
	table_close(catalogRel, NoLock);

	/*
	 * Update pg_attribute.attoptions with "zstd_dictid" => zstd_dictid so the
	 * column knows which dictionary to use at compression time.
	 */
	attRel = table_open(AttributeRelationId, RowExclusiveLock);
	atttup = SearchSysCacheAttNum(relid, attno);
	if (!HeapTupleIsValid(atttup))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column number %d of relation \"%u\" does not exist",
						attno, relid)));

	/* Build new attoptions with zstd_dictid=... */
	def = makeDefElem("zstd_dictid",
					  (Node *) makeString(psprintf("%u", zstd_dictid)),
					  -1);

	attoptionsDatum = SysCacheGetAttr(ATTNUM, atttup,
									  Anum_pg_attribute_attoptions,
									  &isnull);
	newOptions = transformRelOptions(isnull ? (Datum) 0 : attoptionsDatum,
									 list_make1(def),
									 NULL, NULL,
									 false, false);
	/* Validate them (throws error if invalid) */
	(void) attribute_reloptions(newOptions, true);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	repl_val[Anum_pg_attribute_attoptions - 1] = newOptions;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;

	newtuple = heap_modify_tuple(atttup, RelationGetDescr(attRel), repl_val, repl_null, repl_repl);
	CatalogTupleUpdate(attRel, &newtuple->t_self, newtuple);

	heap_freetuple(newtuple);
	ReleaseSysCache(atttup);
	table_close(attRel, NoLock);

	/* Record dependency, relation is depended on this dictionary */
	ObjectAddressSet(dictObj, ZstdDictionariesRelationId, zstd_dictid);
	ObjectAddressSet(relObj, RelationRelationId, relid);
	recordDependencyOn(&relObj, &dictObj, DEPENDENCY_NORMAL);

	pfree(dict_data);
	table_close(rel, NoLock);
	return true;

cleanup_dict:
	pfree(dict_data);
fail:
	table_close(rel, NoLock);

	return false;
#endif
}

/*
 * Acquire a new unique DictId for a relation.
 *
 * Assumes the relation is already locked with ShareRowExclusiveLock,
 * ensuring that concurrent transactions cannot generate duplicate DictIds.
 */
pg_attribute_unused()
static Oid
GetNewDictId(Relation dictRel)
{
	Relation	idxRel;
	Oid			maxDictId = InvalidOid;
	Oid			newDictId;
	SysScanDesc scan;
	HeapTuple	tuple;

	/*
	 * Open the index to read existing DictId values.
	 */
	idxRel = index_open(ZstdDictidIndexId, AccessShareLock);

	/*
	 * Retrieve the maximum existing DictId by scanning in reverse order. This
	 * relies on the index being sorted ascending on zstd_dictid, so scanning
	 * backward finds the largest value first.
	 */
	scan = systable_beginscan_ordered(dictRel,
									  idxRel,
									  SnapshotSelf,
									  0, NULL);

	tuple = systable_getnext_ordered(scan, BackwardScanDirection);
	if (HeapTupleIsValid(tuple))
	{
		Datum		value;
		bool		isNull;

		value = heap_getattr(tuple,
							 Anum_pg_zstd_dictionaries_dictid,
							 RelationGetDescr(dictRel),
							 &isNull);
		if (!isNull)
			maxDictId = DatumGetObjectId(value);
	}
	systable_endscan_ordered(scan);
	index_close(idxRel, AccessShareLock);

	/* Propose new DictId one higher than the max found. */
	newDictId = maxDictId + 1;
	Assert(newDictId != InvalidDictId);

	if (newDictId <= InvalidDictId || newDictId > UINT32_MAX)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("zstd_dictid is not in expected range")));

	return newDictId;
}

/*
 * append_sample
 *
 * Given a sample (raw bytes) and its size, append it to the training data.
 * This function re-allocates (or allocates) the contiguous sample_buffer and
 * the sample_sizes array. It returns true if the new total allocation does not
 * exceed MaxAllocSize, false otherwise.
 */
static bool
append_sample(ZstdTrainingData *dict, const char *sample, size_t sample_size)
{
	if ((dict->total_size + sample_size) > MaxAllocSize)
		return false;

	if (dict->sample_buffer == NULL)
		dict->sample_buffer = palloc(sample_size);
	else
		dict->sample_buffer = repalloc(dict->sample_buffer, dict->total_size + sample_size);

	memcpy(dict->sample_buffer + dict->total_size, sample, sample_size);
	dict->total_size += sample_size;

	if (dict->sample_sizes == NULL)
		dict->sample_sizes = palloc(sizeof(size_t));
	else
		dict->sample_sizes = repalloc(dict->sample_sizes, (dict->nitems + 1) * sizeof(size_t));

	dict->sample_sizes[dict->nitems++] = sample_size;

	return true;
}

/* Common helper for jsonb and text */
static bool
sample_varlena_datum(Datum datum, ZstdTrainingData *dict)
{
	struct varlena *attr = (struct varlena *) PG_DETOAST_DATUM(datum);

	return append_sample(dict, VARDATA_ANY(attr), VARSIZE_ANY_EXHDR(attr));
}

/*
 * std_zstd_sampling_for_jsonb
 *
 * Processes a single jsonb sample.
 * It detoasts the datum, obtains the raw sample (excluding the header),
 * and appends it into the provided ZstdTrainingData structure.
 *
 * Returns true if the sample was successfully appended, false otherwise.
 */
Datum
std_zstd_sampling_for_jsonb(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(sample_varlena_datum(PG_GETARG_DATUM(0), (ZstdTrainingData *) PG_GETARG_POINTER(1)));
}

/*
 * std_zstd_sampling_for_text
 *
 * Processes a single text sample.
 * It detoasts the datum, obtains the raw sample (excluding the header),
 * and appends it into the provided ZstdTrainingData structure.
 *
 * Returns true if the sample was successfully appended, false otherwise.
 */
Datum
std_zstd_sampling_for_text(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(sample_varlena_datum(PG_GETARG_DATUM(0), (ZstdTrainingData *) PG_GETARG_POINTER(1)));
}

/*
 * array_typzstdsampling -- typzstdsampling function for array columns
 */
Datum
array_typzstdsampling(PG_FUNCTION_ARGS)
{
	ArrayType  *array = DatumGetArrayTypeP(PG_GETARG_DATUM(0));
	ZstdTrainingData *dict = (ZstdTrainingData *) PG_GETARG_POINTER(1);
	Datum	   *elements;
	bool	   *nulls;
	int			nelems;
	TypeCacheEntry *elemCache = lookup_type_cache(ARR_ELEMTYPE(array), 0);

	if (!OidIsValid(elemCache->typzstdsampling))
		PG_RETURN_BOOL(false);

	deconstruct_array(array, ARR_ELEMTYPE(array), elemCache->typlen, elemCache->typbyval, elemCache->typalign, &elements, &nulls, &nelems);

	for (int j = 0; j < nelems; j++)
		if (!nulls[j] && !DatumGetBool(OidFunctionCall2(elemCache->typzstdsampling, elements[j], PointerGetDatum(dict))))
			break;

	pfree(elements);
	pfree(nulls);
	PG_RETURN_BOOL(true);
}

Datum
range_typzstdsampling(PG_FUNCTION_ARGS)
{
	RangeType  *range = DatumGetRangeTypeP(PG_GETARG_DATUM(0));
	ZstdTrainingData *dict = (ZstdTrainingData *) PG_GETARG_POINTER(1);
	RangeBound	lower,
				upper;
	bool		empty;

	/* Get information about range type; note column might be a domain */
	TypeCacheEntry *typcache = range_get_typcache(fcinfo, RangeTypeGetOid(range));

	/* If the type does not supply a builder, skip */
	if (!OidIsValid(typcache->rngelemtype->typzstdsampling))
		PG_RETURN_BOOL(false);

	range_deserialize(typcache, range, &lower, &upper, &empty);
	if (empty)
		PG_RETURN_BOOL(false);

	OidFunctionCall2(typcache->rngelemtype->typzstdsampling, lower.val, PointerGetDatum(dict));

	OidFunctionCall2(typcache->rngelemtype->typzstdsampling, upper.val, PointerGetDatum(dict));

	PG_RETURN_BOOL(true);
}

Datum
multirange_typzstdsampling(PG_FUNCTION_ARGS)
{
	MultirangeType *mrange = DatumGetMultirangeTypeP(PG_GETARG_DATUM(0));
	ZstdTrainingData *dict = (ZstdTrainingData *) PG_GETARG_POINTER(1);
	int32		rangeCount;
	RangeType **ranges;

	/* Get information about multirange type; note column might be a domain */
	TypeCacheEntry *typcache = multirange_get_typcache(fcinfo, MultirangeTypeGetOid(mrange));

	/* If the type does not supply a builder, skip */
	if (!OidIsValid(typcache->rngtype->typzstdsampling))
		PG_RETURN_BOOL(false);

	/* Deserialize the multirange into an array of RangeType pointers */
	multirange_deserialize(typcache->rngtype, mrange, &rangeCount, &ranges);

	for (int j = 0; j < rangeCount; j++)
		if (!DatumGetBool(OidFunctionCall2(typcache->rngtype->typzstdsampling, RangeTypePGetDatum(ranges[j]), PointerGetDatum(dict))))
			break;

	PG_RETURN_BOOL(true);
}

Datum
composite_typzstdsampling(PG_FUNCTION_ARGS)
{
	HeapTupleHeader th = DatumGetHeapTupleHeader(PG_GETARG_DATUM(0));
	ZstdTrainingData *dict = (ZstdTrainingData *) PG_GETARG_POINTER(1);

	TupleDesc	tupdesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(th), HeapTupleHeaderGetTypMod(th));
	HeapTupleData tuple = {.t_data = th,.t_len = HeapTupleHeaderGetDatumLength(th),.t_tableOid = InvalidOid};

	ItemPointerSetInvalid(&tuple.t_self);

	for (int i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		bool		isnull;
		Datum		fieldDatum;

		if (attr->attisdropped || attr->atthasmissing)
			continue;

		fieldDatum = heap_getattr(&tuple, i + 1, tupdesc, &isnull);

		if (!isnull)
		{
			/* Look up the type cache entry for the attribute's type */
			TypeCacheEntry *typcache = lookup_type_cache(attr->atttypid, 0);

			if (OidIsValid(typcache->typzstdsampling) && !DatumGetBool(OidFunctionCall2(typcache->typzstdsampling, fieldDatum, PointerGetDatum(dict))))
				break;
		}
	}

	ReleaseTupleDesc(tupdesc);
	PG_RETURN_BOOL(true);
}

Datum
build_zstd_dict_for_attribute(PG_FUNCTION_ARGS)
{
#ifndef USE_ZSTD
	PG_RETURN_BOOL(false);
#else
	text	   *tablename = PG_GETARG_TEXT_PP(0);
	AttrNumber	attno = PG_GETARG_INT32(1);

	/* Look up table name. */
	RangeVar   *tablerel = makeRangeVarFromNameList(textToQualifiedNameList(tablename));
	Oid			tableoid = RangeVarGetRelid(tablerel, NoLock, false);

	bool		ret = build_zstd_dictionary_internal(tableoid, attno);

	PG_RETURN_BOOL(ret);
#endif
}

/*
 * generate_zstd_dictionaries_for_relation
 *
 * Opens the relation identified by relid, iterates over its attributes,
 * and for each valid (non-dropped, user-defined) attribute, calls
 * build_zstd_dictionary_internal.
 */
void
generate_zstd_dictionaries_for_relation(Oid relid)
{
	Relation	rel;
	TupleDesc	tupdesc;

	/* Start a new transaction */
	StartTransactionCommand();

	/* Push an active snapshot toast want snapshot */
	PushActiveSnapshot(GetTransactionSnapshot());

	/* Open the relation using table_open (or relation_open) */
	rel = table_open(relid, AccessShareLock);
	tupdesc = RelationGetDescr(rel);

	/* Iterate over all attributes of the relation */
	for (int i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);

		/* Skip dropped attributes and system columns (attnum <= 0) */
		if (attr->attisdropped || attr->attnum <= 0)
			continue;

		/* Call your dictionary-building function for this attribute */
		build_zstd_dictionary_internal(relid, attr->attnum);

		/*
		 * If build_zstd_dictionary_internal performs modifications that
		 * subsequent iterations must see, use CommandCounterIncrement to
		 * update the visibility of those changes.
		 */
		CommandCounterIncrement();
	}

	/* Close the relation and release the lock */
	table_close(rel, NoLock);

	/* Pop the snapshot to clean up */
	PopActiveSnapshot();

	/* Commit the transaction */
	CommitTransactionCommand();
}

/*
 * get_zstd_dict - Fetches the ZSTD dictionary from the catalog
 *
 * zstd_dictid: The Oid of the dictionary to fetch.
 *
 * Returns: A pointer to a bytea containing the dictionary data.
 */
bytea *
get_zstd_dict(Oid zstd_dictid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isNull;
	bytea	   *dict_bytea;
	Size		bytea_len;
	bytea	   *result;

	tuple = SearchSysCache1(ZSTDDICTIDOID, ObjectIdGetDatum(zstd_dictid));
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR, (errmsg("Cache lookup failed for zstd_dictid %u", zstd_dictid)));

	datum = SysCacheGetAttr(ZSTDDICTIDOID, tuple, Anum_pg_zstd_dictionaries_dict, &isNull);
	if (isNull)
		ereport(ERROR, (errmsg("Dictionary not found for zstd_dictid %u", zstd_dictid)));

	dict_bytea = DatumGetByteaP(datum);
	bytea_len = VARSIZE(dict_bytea);

	result = palloc(bytea_len);
	memcpy(result, dict_bytea, bytea_len);

	ReleaseSysCache(tuple);

	return result;
}
