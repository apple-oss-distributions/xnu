/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* IOSymbol.cpp created by gvdl on Fri 1998-11-17 */

#define IOKIT_ENABLE_SHARED_PTR

#include <string.h>
#include <sys/cdefs.h>

#include <kern/bits.h>
#include <kern/locks.h>
#include <kern/smr_hash.h>
#include <kern/thread_call.h>

#if defined(__arm64__)
#include <arm64/amcc_rorgn.h> /* rorgn_contains */
#endif
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/c++/OSLib.h>
#include <os/cpp_util.h>
#include <os/hash.h>
#include <string.h>

static ZONE_DEFINE(OSSymbol_zone, "iokit.OSSymbol", sizeof(OSSymbol), ZC_NONE);
static LCK_GRP_DECLARE(lock_group, "OSSymbolPool");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"

/*
 * This implements a relativistic hash table, using <kern/smr.h> as underlying
 * safe memory reclamation scheme.
 *
 * (https://www.usenix.org/legacy/event/atc11/tech/final_files/Triplett.pdf)
 *
 * One twist is that the OSSymbol_smr_free() callback must be
 * preemption-disabled safe, which means the `kfree_data()` it calls _MUST_ be
 * smaller than KALLOC_SAFE_ALLOC_SIZE. To deal with that, if a Symbol is made
 * with a string that is much larger (should be rare), these go on a lock-based
 * "huge" queue.
 */
class OSSymbolPool
{
	/* empirically most devices have at least 10+k symbols */
	static constexpr uint32_t MIN_SIZE = 4096;

	static inline smrh_key_t
	OSSymbol_get_key(const OSSymbol *sym)
	{
		return {
			       .smrk_string = sym->string,
			       .smrk_len    = (size_t)(sym->length - 1)
		};
	}

	static uint32_t
	OSSymbol_obj_hash(const struct smrq_slink *link, uint32_t seed)
	{
		OSSymbol *sym = __container_of(link, OSSymbol, hashlink);

		return smrh_key_hash_str(OSSymbol_get_key(sym), seed);
	}

	static bool
	OSSymbol_obj_equ(const struct smrq_slink *link, smrh_key_t key)
	{
		OSSymbol *sym = __container_of(link, OSSymbol, hashlink);

		return smrh_key_equ_str(OSSymbol_get_key(sym), key);
	}

	static bool
	OSSymbol_obj_try_get(void *obj)
	{
		OSSymbol *sym = (OSSymbol *)obj;

		return (sym->flags & kOSSSymbolPermanent) ||
		       sym->taggedTryRetain(nullptr);
	}

	SMRH_TRAITS_DEFINE_STR(hash_traits, OSSymbol, hashlink,
	    .domain      = &smr_iokit,
	    .obj_hash    = OSSymbol_obj_hash,
	    .obj_equ     = OSSymbol_obj_equ,
	    .obj_try_get = OSSymbol_obj_try_get);

	mutable lck_mtx_t _mutex;
	struct smr_hash   _hash;
	smrq_slist_head   _huge_head;
	thread_call_t     _tcall;
	uint32_t          _hugeCount = 0;
	bool              _tcallScheduled;

private:

	inline void
	lock() const
	{
		lck_mtx_lock(&_mutex);
	}

	inline void
	unlock() const
	{
		lck_mtx_unlock(&_mutex);
	}

	inline bool
	shouldShrink() const
	{
		/* shrink if there are more than 2 buckets per 1 symbol */
		return smr_hash_serialized_should_shrink(&_hash, MIN_SIZE, 2, 1);
	}

	inline bool
	shouldGrow() const
	{
		/* shrink if there less more than 1 bucket per 4 symbol */
		return smr_hash_serialized_should_grow(&_hash, 1, 4);
	}

public:

	static void rehash(thread_call_param_t, thread_call_param_t);
	inline static OSSymbolPool &instance() __pure2;

	OSSymbolPool()
	{
		lck_mtx_init(&_mutex, &lock_group, LCK_ATTR_NULL);

		smr_hash_init(&_hash, MIN_SIZE);
		smrq_init(&_huge_head);

		_tcall = thread_call_allocate_with_options(rehash, this,
		    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	}
	OSSymbolPool(const OSSymbolPool &) = delete;
	OSSymbolPool(OSSymbolPool &&) = delete;
	OSSymbolPool &operator=(const OSSymbolPool &) = delete;
	OSSymbolPool &operator=(OSSymbolPool &&) = delete;

	~OSSymbolPool() = delete;

	OSSharedPtr<const OSSymbol> findSymbol(smrh_key_t key) const;

	void insertSymbol(
		OSSharedPtr<OSSymbol> &sym,
		smrh_key_t key,
		bool makePermanent = false);

	void removeSymbol(OSSymbol *sym);

	void rehash();

	void checkForPageUnload(void *startAddr, void *endAddr);
};

static _Alignas(OSSymbolPool) uint8_t OSSymbolPoolStorage[sizeof(OSSymbolPool)];

OSSymbolPool &
OSSymbolPool::instance()
{
	return reinterpret_cast<OSSymbolPool &>(OSSymbolPoolStorage);
}

static inline bool
OSSymbol_is_huge(size_t size)
{
	return size > KALLOC_SAFE_ALLOC_SIZE;
}

OSSharedPtr<const OSSymbol>
OSSymbolPool::findSymbol(smrh_key_t key) const
{
	OSSymbol *sym;
	OSSharedPtr<const OSSymbol> ret;

	if (!OSSymbol_is_huge(key.smrk_len)) {
		char tmp_buf[128]; /* empirically all keys are < 110 bytes */
		char *copy_s = NULL;

		/*
		 * rdar://105075708: the key might be in pageable memory,
		 * and smr_hash_get() disable preemption which prevents
		 * faulting the memory.
		 */
		if (key.smrk_len <= sizeof(tmp_buf)) {
			memcpy(tmp_buf, key.smrk_opaque, key.smrk_len);
			key.smrk_string = tmp_buf;
		} else {
			copy_s = (char *)kalloc_data(key.smrk_len,
			    Z_WAITOK_ZERO_NOFAIL);
			memcpy(copy_s, key.smrk_opaque, key.smrk_len);
			key.smrk_string = copy_s;
		}
		sym = smr_hash_get(&_hash, key, &hash_traits);
		if (copy_s) {
			kfree_data(copy_s, key.smrk_len);
		}
	} else {
		lock();
		sym = (OSSymbol *)__smr_hash_serialized_find(&_huge_head, key,
		    &hash_traits.smrht);
		if (sym && !OSSymbol_obj_try_get(sym)) {
			sym = NULL;
		}
		unlock();
	}

	if (sym) {
		ret.reset(sym, OSNoRetain);
	}

	return ret;
}

void
OSSymbolPool::insertSymbol(
	OSSharedPtr<OSSymbol>  &symToInsert,
	smrh_key_t              key,
	bool                    make_permanent)
{
	OSSymbol *sym;

	/* make sure no one ever subclassed OSSymbols */
	zone_require(OSSymbol_zone, symToInsert.get());

	symToInsert->flags |= kOSSSymbolHashed;
	if (make_permanent) {
		symToInsert->flags |= kOSSSymbolPermanent;
	}

	lock();

	if (!OSSymbol_is_huge(key.smrk_len)) {
		sym = smr_hash_serialized_get_or_insert(&_hash, key,
		    &symToInsert->hashlink, &hash_traits);

		if (shouldGrow() && !_tcallScheduled &&
		    startup_phase >= STARTUP_SUB_THREAD_CALL) {
			_tcallScheduled = true;
			thread_call_enter(_tcall);
		}
	} else {
		sym = (OSSymbol *)__smr_hash_serialized_find(&_huge_head, key,
		    &hash_traits.smrht);
		if (!sym || !OSSymbol_obj_try_get(sym)) {
			smrq_serialized_insert_head(&_huge_head,
			    &symToInsert->hashlink);
			_hugeCount++;
			sym = NULL;
		}
	}

	unlock();

	if (sym) {
		symToInsert->flags &= ~(kOSSSymbolHashed | kOSSSymbolPermanent);
		symToInsert.reset(sym, OSNoRetain);
	}
}

void
OSSymbolPool::removeSymbol(OSSymbol *sym)
{
	lock();

	assert(sym->flags & kOSSSymbolHashed);
	sym->flags &= ~kOSSSymbolHashed;

	if (!OSSymbol_is_huge(sym->length)) {
		smr_hash_serialized_remove(&_hash, &sym->hashlink, &hash_traits);

		if (shouldShrink() && !_tcallScheduled &&
		    startup_phase >= STARTUP_SUB_THREAD_CALL) {
			_tcallScheduled = true;
			thread_call_enter(_tcall);
		}
	} else {
		smrq_serialized_remove(&_huge_head, &sym->hashlink);
		_hugeCount--;
	}

	unlock();
}

void
OSSymbolPool::rehash(thread_call_param_t arg0, thread_call_param_t arg1 __unused)
{
	reinterpret_cast<OSSymbolPool *>(arg0)->rehash();
}

void
OSSymbolPool::rehash()
{
	lock();
	_tcallScheduled = false;

	if (shouldShrink()) {
		smr_hash_shrink_and_unlock(&_hash, &_mutex, &hash_traits);
	} else if (shouldGrow()) {
		smr_hash_grow_and_unlock(&_hash, &_mutex, &hash_traits);
	} else {
		unlock();
	}
}

void
OSSymbolPool::checkForPageUnload(void *startAddr, void *endAddr)
{
	OSSymbol *sym;
	char *s;
	bool mustSync = false;

	lock();
	smr_hash_foreach(sym, &_hash, &hash_traits) {
		if (sym->string >= startAddr && sym->string < endAddr) {
			assert(sym->flags & kOSStringNoCopy);

			s = (char *)kalloc_data(sym->length,
			    Z_WAITOK_ZERO);
			if (s) {
				memcpy(s, sym->string, sym->length);
				/*
				 * make sure the memcpy is visible for readers
				 * who dereference `string` below.
				 *
				 * We can't use os_atomic_store(&..., release)
				 * because OSSymbol::string is PACed
				 */
				os_atomic_thread_fence(release);
			}
			sym->string = s;
			sym->flags &= ~kOSStringNoCopy;
			mustSync = true;
		}
	}

	unlock();

	/* Make sure no readers can see stale pointers that we rewrote */
	if (mustSync) {
		smr_iokit_synchronize();
	}
}

#pragma clang diagnostic pop /* -Winvalid-offsetof */

/*
 *********************************************************************
 * From here on we are actually implementing the OSSymbol class
 *********************************************************************
 */
#define super OSString

OSDefineMetaClassWithInit(OSSymbol, OSString, OSSymbol::initialize());
OSMetaClassConstructorInit(OSSymbol, OSString, OSSymbol::initialize());
OSDefineBasicStructors(OSSymbol, OSString)
OSMetaClassDefineReservedUnused(OSSymbol, 0);
OSMetaClassDefineReservedUnused(OSSymbol, 1);
OSMetaClassDefineReservedUnused(OSSymbol, 2);
OSMetaClassDefineReservedUnused(OSSymbol, 3);
OSMetaClassDefineReservedUnused(OSSymbol, 4);
OSMetaClassDefineReservedUnused(OSSymbol, 5);
OSMetaClassDefineReservedUnused(OSSymbol, 6);
OSMetaClassDefineReservedUnused(OSSymbol, 7);

static void
OSSymbol_smr_free(void *sym, vm_size_t size __unused)
{
	reinterpret_cast<OSSymbol *>(sym)->smr_free();
}

void
OSSymbol::initialize()
{
	zone_enable_smr(OSSymbol_zone, &smr_iokit, &OSSymbol_smr_free);
	new (OSSymbolPoolStorage) OSSymbolPool();
}

bool
OSSymbol::initWithCStringNoCopy(const char *)
{
	return false;
}
bool
OSSymbol::initWithCString(const char *)
{
	return false;
}
bool
OSSymbol::initWithString(const OSString *)
{
	return false;
}

OSSharedPtr<const OSSymbol>
OSSymbol::withString(const OSString *aString)
{
	// This string may be a OSSymbol already, cheap check.
	if (OSDynamicCast(OSSymbol, aString)) {
		OSSharedPtr<const OSSymbol> aStringNew((const OSSymbol *)aString, OSRetain);
		return aStringNew;
	} else if (((const OSSymbol *) aString)->flags & kOSStringNoCopy) {
		return OSSymbol::withCStringNoCopy(aString->getCStringNoCopy());
	} else {
		return OSSymbol::withCString(aString->getCStringNoCopy());
	}
}

OSSharedPtr<const OSSymbol>
OSSymbol::withCString(const char *cString)
{
	auto &pool = OSSymbolPool::instance();
	smrh_key_t key = {
		.smrk_string = cString,
		.smrk_len    = strnlen(cString, kMaxStringLength),
	};
	bool permanent = false;

	if (key.smrk_len >= kMaxStringLength) {
		return nullptr;
	}

	auto symbol = pool.findSymbol(key);
	if (__probable(symbol)) {
		return symbol;
	}

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	/*
	 * Empirically, symbols which string is from the rorgn part of the
	 * kernel are asked about all the time.
	 *
	 * Making them noCopy + permanent avoids a significant amount of
	 * useless refcounting traffic.
	 *
	 * On embedded, this policy causes about 200 extra symbols to be made
	 * from baseline (~6k), but avoiding the string copies saves about 60k.
	 */
	permanent = rorgn_contains((vm_offset_t)cString, key.smrk_len + 1, false);
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

	/*
	 * can't use OSString::initWithCString* because it calls
	 * OSObject::init() which tries to enroll in IOTracking if it's on.
	 */

	auto newSymb = OSMakeShared<OSSymbol>();

	if (permanent) {
		newSymb->flags  = kOSStringNoCopy;
		newSymb->length = (uint32_t)(key.smrk_len + 1);
		newSymb->string = const_cast<char *>(cString);
		pool.insertSymbol(/* inout */ newSymb, key, permanent);
	} else if (char *s = (char *)kalloc_data(key.smrk_len + 1, Z_WAITOK_ZERO)) {
		memcpy(s, cString, key.smrk_len);
		newSymb->flags  = 0;
		newSymb->length = (uint32_t)(key.smrk_len + 1);
		newSymb->string = s;
		pool.insertSymbol(/* inout */ newSymb, key, permanent);
	} else {
		newSymb.reset();
	}

	return os::move(newSymb); // return the newly created & inserted symbol.
}

OSSharedPtr<const OSSymbol>
OSSymbol::withCStringNoCopy(const char *cString)
{
	auto &pool = OSSymbolPool::instance();
	smrh_key_t key = {
		.smrk_string = cString,
		.smrk_len    = strnlen(cString, kMaxStringLength),
	};
	bool permanent = false;

	if (key.smrk_len >= kMaxStringLength) {
		return nullptr;
	}

	auto symbol = pool.findSymbol(key);
	if (__probable(symbol)) {
		return symbol;
	}

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	permanent = rorgn_contains((vm_offset_t)cString, key.smrk_len + 1, false);
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

	auto newSymb = OSMakeShared<OSSymbol>();

	/*
	 * can't use OSString::initWithCStringNoCopy because it calls
	 * OSObject::init() which tries to enrol in IOTracking if it's on.
	 */
	newSymb->flags  = kOSStringNoCopy;
	newSymb->length = (uint32_t)(key.smrk_len + 1);
	newSymb->string = const_cast<char *>(cString);
	pool.insertSymbol(/* inout */ newSymb, key, permanent);

	return os::move(newSymb); // return the newly created & inserted symbol.
}

OSSharedPtr<const OSSymbol>
OSSymbol::existingSymbolForString(const OSString *aString)
{
	if (!aString) {
		return NULL;
	}
	if (OSDynamicCast(OSSymbol, aString)) {
		OSSharedPtr<const OSSymbol> aStringNew((const OSSymbol *)aString, OSRetain);
		return aStringNew;
	}

	smrh_key_t key = {
		.smrk_string = aString->getCStringNoCopy(),
		.smrk_len    = aString->getLength(),
	};
	return OSSymbolPool::instance().findSymbol(key);
}

OSSharedPtr<const OSSymbol>
OSSymbol::existingSymbolForCString(const char *cString)
{
	smrh_key_t key = {
		.smrk_string = cString,
		.smrk_len    = strlen(cString),
	};
	return OSSymbolPool::instance().findSymbol(key);
}

void
OSSymbol::checkForPageUnload(void *startAddr, void *endAddr)
{
	OSSymbolPool::instance().checkForPageUnload(startAddr, endAddr);
}

void
OSSymbol::taggedRetain(const void *tag) const
{
	if ((flags & kOSSSymbolPermanent) == 0) {
		super::taggedRetain(tag);
	}
}

void
OSSymbol::taggedRelease(const void *tag) const
{
	if ((flags & kOSSSymbolPermanent) == 0) {
		super::taggedRelease(tag);
	}
}

void
OSSymbol::taggedRelease(const void *tag, const int when) const
{
	if ((flags & kOSSSymbolPermanent) == 0) {
		super::taggedRelease(tag, when);
	}
}

void *
OSSymbol::operator new(size_t size __unused)
{
	return zalloc_smr(OSSymbol_zone, Z_WAITOK_ZERO_NOFAIL);
}

void
OSSymbol::operator delete(void *mem, size_t size)
{
	/*
	 * OSSymbol dying is this sequence:
	 *
	 * OSSymbol::taggedRelease() hits 0,
	 * which calls OSSymbol::free(),
	 * which calls zfree_smr().
	 *
	 * At this stage, the memory of the OSSymbol is on a deferred
	 * reclamation queue.
	 *
	 * When the memory is being recycled by zalloc, OSSymbol::smr_free()
	 * is called which terminates with a delete call and only needs
	 * to zero said memory given that the memory has already been
	 * returned to the allocator.
	 */
	bzero(mem, size);
}

void
OSSymbol::smr_free()
{
	/*
	 * This is called when the object is getting reused
	 */

	if (!(flags & kOSStringNoCopy) && string) {
		kfree_data(string, length);
	}

	/*
	 * Note: we do not call super::free() on purpose because
	 *       it would call OSObject::free() which tries to support
	 *       iotracking. iotracking is fundamentally incompatible
	 *       with SMR, so we on purpose do not call into these.
	 *
	 *       to debug OSSymbol leaks etc, the zone logging feature
	 *       can be used instead on the iokit.OSSymbol zone.
	 */
	OSSymbol::gMetaClass.instanceDestructed();

	delete this;
}

void
OSSymbol::free()
{
	bool freeNow = true;

	if (flags & kOSSSymbolHashed) {
		OSSymbolPool::instance().removeSymbol(this);
		freeNow = OSSymbol_is_huge(length);
	}

	if (freeNow && !(flags & kOSStringNoCopy) && string) {
		/*
		 * If the element isn't in the hash, it was a failed insertion
		 * racing, and no one will every do a hazardous access,
		 * so we can clean up the string right away.
		 *
		 * If it is huge, then it is not looked up via SMR but under
		 * locks, so we can free right now (actually _must_ because
		 * this free is not preemption disabled safe and can't be done
		 * in smr_free())
		 */
		kfree_data(string, length);
		assert(string == nullptr); /* kfree_data nils out */
	}

	(zfree_smr)(OSSymbol_zone, this);
}

uint32_t
OSSymbol::hash() const
{
	assert(!OSSymbol_is_huge(length));
	return os_hash_jenkins(string, length - 1);
}

bool
OSSymbol::isEqualTo(const char *aCString) const
{
	return super::isEqualTo(aCString);
}

bool
OSSymbol::isEqualTo(const OSSymbol *aSymbol) const
{
	return aSymbol == this;
}

bool
OSSymbol::isEqualTo(const OSMetaClassBase *obj) const
{
	OSSymbol *  sym;
	OSString *  str;

	if ((sym = OSDynamicCast(OSSymbol, obj))) {
		return isEqualTo(sym);
	} else if ((str = OSDynamicCast(OSString, obj))) {
		return super::isEqualTo(str);
	} else {
		return false;
	}
}

unsigned int
OSSymbol::bsearch(
	const void *  key,
	const void *  array,
	unsigned int  arrayCount,
	size_t        memberSize)
{
	const void **p;
	unsigned int baseIdx = 0;
	unsigned int lim;

	for (lim = arrayCount; lim; lim >>= 1) {
		p = (typeof(p))(((uintptr_t) array) + (baseIdx + (lim >> 1)) * memberSize);
		if (key == *p) {
			return baseIdx + (lim >> 1);
		}
		if (key > *p) {
			// move right
			baseIdx += (lim >> 1) + 1;
			lim--;
		}
		// else move left
	}
	// not found, insertion point here
	return baseIdx + (lim >> 1);
}

#if DEBUG || DEVELOPMENT
static int
iokit_symbol_basic_test(int64_t size, int64_t *out)
{
	OSSharedPtr<const OSSymbol> sym1;
	OSSharedPtr<const OSSymbol> sym2;
	char *data;

	data = (char *)kalloc_data(size, Z_WAITOK);
	if (!data) {
		return ENOMEM;
	}

	memset(data, 'A', size - 1);
	data[size - 1] = '\0';

	sym1 = OSSymbol::withCString(data);
	if (sym1 == nullptr) {
		return ENOMEM;
	}
	assert(sym1->getLength() == size - 1);

	sym2 = OSSymbol::withCString(data);
	assert(sym1 == sym2);

	sym2.reset();
	sym1.reset();

	*out = 1;
	return 0;
}
SYSCTL_TEST_REGISTER(iokit_symbol_basic, iokit_symbol_basic_test);
#endif /* DEBUG || DEVELOPMENT */
