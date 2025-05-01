"""
XNU Collection iterators
"""
from .cvalue import gettype
from .standard import xnu_format

from abc import ABCMeta, abstractmethod, abstractproperty


#
# Note to implementers
# ~~~~~~~~~~~~~~~~~~~~
#
# Iterators must be named iter_* in accordance with typical python API naming
#
# The "root" or "head" of the collection must be passed by reference
# and not by pointer.
#
# Returned elements must be references to the element type,
# and not pointers.
#
# Intrusive data types should ask for an "element type" (as an SBType),
# and a field name or path, and use SBType.xContainerOfTransform
# to cache the transform to apply for the entire iteration.
#


def iter_linked_list(head_value, next_field_or_path,
        first_field_or_path = None):
    """
    Iterates a NULL-terminated linked list.

        Assuming these C types:

            struct container {
                struct node *list1_head;
                struct node *list2_head;
            }

            struct node {
                struct node *next;
            }

        and "v" is an SBValue to a `struct container` type,
        enumerating list1 is:

            iter_linked_list(v, 'next', 'list1_head')

        if "v" is a `struct node *` directly, then the enumeration
        becomes:

            iter_linked_list(v, 'next')


    @param head_value (SBValue)
        a reference to the list head.

    @param next_field_or_path (str)
        The name of (or path to if starting with '.')
        the field linking to the next element.

    @param first_field_or_path (str or None)
        The name of (or path to if starting with '.')
        the field from @c head_value holding the pointer
        to the first element of the list.
    """

    if first_field_or_path is None:
        elt = head_value
    elif first_field_or_path[0] == '.':
        elt = head_value.chkGetValueForExpressionPath(first_field_or_path)
    else:
        elt = head_value.chkGetChildMemberWithName(first_field_or_path)

    if next_field_or_path[0] == '.':
        while elt.GetValueAsAddress():
            elt = elt.Dereference()
            yield elt
            elt = elt.chkGetValueForExpressionPath(next_field_or_path)
    else:
        while elt.GetValueAsAddress():
            elt = elt.Dereference()
            yield elt
            elt = elt.chkGetChildMemberWithName(next_field_or_path)


def iter_queue_entries(head_value, elt_type, field_name_or_path, backwards=False):
    """
    Iterate over a queue of entries (<kern/queue.h> method 1)

    @param head_value (SBValue)
        a reference to the list head (queue_head_t)

    @param elt_type (SBType)
        The type of the elements on the chain

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct mpsc_queue_chain linkage.

    @param backwards (bool)
         Whether the walk is forward or backwards
    """

    stop = head_value.GetLoadAddress()
    elt  = head_value
    key  = 'prev' if backwards else 'next'

    transform = elt_type.xContainerOfTransform(field_name_or_path)

    while True:
        elt  = elt.chkGetChildMemberWithName(key)
        addr = elt.GetValueAsAddress()
        if addr == 0 or addr == stop:
            break
        elt = elt.Dereference()
        yield transform(elt)


def iter_queue(head_value, elt_type, field_name_or_path, backwards=False, unpack=None):
    """
    Iterate over queue of elements (<kern/queue.h> method 2)

    @param head_value (SBValue)
        A reference to the list head (queue_head_t)

    @param elt_type (SBType)
        The type of the elements on the chain

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct mpsc_queue_chain linkage.

    @param backwards (bool)
         Whether the walk is forward or backwards

    @param unpack (Function or None)
        A function to unpack the pointer or None.
    """

    stop = head_value.GetLoadAddress()
    elt  = head_value
    key  = '.prev' if backwards else '.next'
    addr = elt.xGetScalarByPath(key)
    if field_name_or_path[0] == '.':
        path = field_name_or_path + key
    else:
        path = "." + field_name_or_path + key

    while True:
        if unpack is not None:
            addr = unpack(addr)
        if addr == 0 or addr == stop:
            break

        elt  = elt.xCreateValueFromAddress('element', addr, elt_type)
        addr = elt.xGetScalarByPath(path)
        yield elt


def iter_circle_queue(head_value, elt_type, field_name_or_path, backwards=False):
    """
    Iterate over a queue of entries (<kern/circle_queue.h>)

    @param head_value (SBValue)
        a reference to the list head (circle_queue_head_t)

    @param elt_type (SBType)
        The type of the elements on the chain

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct mpsc_queue_chain linkage.

    @param backwards (bool)
         Whether the walk is forward or backwards
    """

    elt  = head_value.chkGetChildMemberWithName('head')
    stop = elt.GetValueAsAddress()
    key  = 'prev' if backwards else 'next'

    transform = elt_type.xContainerOfTransform(field_name_or_path)

    if stop:
        if backwards:
            elt  = elt.chkGetValueForExpressionPath('->prev')
            stop = elt.GetValueAsAddress()

        while True:
            elt = elt.Dereference()
            yield transform(elt)

            elt  = elt.chkGetChildMemberWithName(key)
            addr = elt.GetValueAsAddress()
            if addr == 0 or addr == stop:
                break


def iter_mpsc_queue(head_value, elt_type, field_name_or_path):
    """
    Iterates a struct mpsc_queue_head

    @param head_value (SBValue)
        A struct mpsc_queue_head value.

    @param elt_type (SBType)
        The type of the elements on the chain.

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct mpsc_queue_chain linkage.

    @returns (generator)
        An iterator for the MPSC queue.
    """

    transform = elt_type.xContainerOfTransform(field_name_or_path)

    return (transform(e) for e in iter_linked_list(
        head_value, 'mpqc_next', '.mpqh_head.mpqc_next'
    ))


class iter_priority_queue(object):
    """
    Iterates any of the priority queues from <kern/priority_queue.h>

    @param head_value (SBValue)
        A struct priority_queue* value.

    @param elt_type (SBType)
        The type of the elements on the chain.

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct priority_queue_entry* linkage.

    @returns (generator)
        An iterator for the priority queue.
    """

    def __init__(self, head_value, elt_type, field_name_or_path):
        self.transform = elt_type.xContainerOfTransform(field_name_or_path)

        self.gen   = iter_linked_list(head_value, 'next', 'pq_root')
        self.queue = []

    def __iter__(self):
        return self

    def __next__(self):
        queue = self.queue
        elt   = next(self.gen, None)

        if elt is None:
            if not len(queue):
                raise StopIteration
            elt = queue.pop()
            self.gen = iter_linked_list(elt, 'next', 'next')

        addr = elt.xGetScalarByName('child')
        if addr:
            queue.append(elt.xCreateValueFromAddress(
                None, addr & 0xffffffffffffffff, elt.GetType()))

        return self.transform(elt)

def iter_SLIST_HEAD(head_value, link_field):
    """ Specialized version of iter_linked_list() for <sys/queue.h> SLIST_HEAD """

    next_path = ".{}.sle_next".format(link_field)
    return (e for e in iter_linked_list(head_value, next_path, "slh_first"))

def iter_LIST_HEAD(head_value, link_field):
    """ Specialized version of iter_linked_list() for <sys/queue.h> LIST_HEAD """

    next_path = ".{}.le_next".format(link_field)
    return (e for e in iter_linked_list(head_value, next_path, "lh_first"))

def iter_STAILQ_HEAD(head_value, link_field):
    """ Specialized version of iter_linked_list() for <sys/queue.h> STAILQ_HEAD """

    next_path = ".{}.stqe_next".format(link_field)
    return (e for e in iter_linked_list(head_value, next_path, "stqh_first"))

def iter_TAILQ_HEAD(head_value, link_field):
    """ Specialized version of iter_linked_list() for <sys/queue.h> TAILQ_HEAD """

    next_path = ".{}.tqe_next".format(link_field)
    return (e for e in iter_linked_list(head_value, next_path, "tqh_first"))

def iter_SYS_QUEUE_HEAD(head_value, link_field):
    """ Specialized version of iter_linked_list() for any <sys/queue> *_HEAD """

    field  = head_value.rawGetType().GetFieldAtIndex(0).GetName()
    next_path = ".{}.{}e_next".format(link_field, field.partition('_')[0])
    return (e for e in iter_linked_list(head_value, next_path, field))


class RB_HEAD(object):
    """
    Class providing utilities to manipulate a collection made with RB_HEAD()
    """

    def __init__(self, rbh_root_value, link_field, cmp):
        """
        Create an rb-tree wrapper

        @param rbh_root_value (SBValue)
            A value to an RB_HEAD() field

        @param link_field (str)
            The name of the RB_ENTRY() field in the elements

        @param cmp (function)
            The comparison function between a linked element,
            and a key
        """

        self.root_sbv = rbh_root_value.chkGetChildMemberWithName('rbh_root')
        self.field    = link_field
        self.cmp      = cmp
        self.etype    = self.root_sbv.GetType().GetPointeeType()

    def _parent(self, elt):
        RB_COLOR_MASK = 0x1

        path   = "." + self.field + ".rbe_parent"
        parent = elt.chkGetValueForExpressionPath(path)
        paddr  = parent.GetValueAsAddress()

        if paddr == 0:
            return None, 0

        if paddr & RB_COLOR_MASK == 0:
            return parent.Dereference(), paddr

        paddr &= ~RB_COLOR_MASK
        return parent.xCreateValueFromAddress(None, paddr, self.etype), paddr

    def _sibling(self, elt, rbe_left, rbe_right):

        field = self.field
        lpath = "." + field + rbe_left
        rpath = "." + field + rbe_right

        e_r = elt.chkGetValueForExpressionPath(rpath)
        if e_r.GetValueAsAddress():
            #
            # IF (RB_RIGHT(elm, field)) {
            #     elm = RB_RIGHT(elm, field);
            #     while (RB_LEFT(elm, field))
            #         elm = RB_LEFT(elm, field);
            #

            path = "->" + field + rbe_left
            res = e_r
            e_l = res.chkGetValueForExpressionPath(path)
            while e_l.GetValueAsAddress():
                res = e_l
                e_l = res.chkGetValueForExpressionPath(path)

            return res.Dereference()

        eaddr = elt.GetLoadAddress()
        e_p, paddr = self._parent(elt)

        if paddr:
            #
            # IF (RB_GETPARENT(elm) &&
            #     (elm == RB_LEFT(RB_GETPARENT(elm), field)))
            #         elm = RB_GETPARENT(elm)
            #

            if e_p.xGetScalarByPath(lpath) == eaddr:
                return e_p

            #
            # WHILE (RB_GETPARENT(elm) &&
            #     (elm == RB_RIGHT(RB_GETPARENT(elm), field)))
            #         elm = RB_GETPARENT(elm);
            # elm = RB_GETPARENT(elm);
            #

            while paddr:
                if e_p.xGetScalarByPath(rpath) != eaddr:
                    return e_p

                eaddr = paddr
                e_p, paddr = self._parent(e_p)

        return None

    def _find(self, key):
        elt = self.root_sbv
        f   = self.field
        le  = None
        ge  = None

        while elt.GetValueAsAddress():
            elt = elt.Dereference()
            rc  = self.cmp(elt, key)
            if rc == 0:
                return elt, elt, elt

            if rc < 0:
                ge  = elt
                elt = elt.chkGetValueForExpressionPath("->" + f + ".rbe_left")
            else:
                le  = elt
                elt = elt.chkGetValueForExpressionPath("->" + f + ".rbe_right")

        return le, None, ge

    def _minmax(self, direction):
        """ Returns the first element in the tree """

        elt  = self.root_sbv
        res  = None
        path = "->" + self.field + direction

        while elt.GetValueAsAddress():
            res = elt
            elt = elt.chkGetValueForExpressionPath(path)

        return res.Dereference() if res is not None else None

    def find_lt(self, key):
        """ Find the element smaller than the specified key """

        elt, _, _ = self._find(key)
        return self.prev(elt) if elt is not None else None

    def find_le(self, key):
        """ Find the element smaller or equal to the specified key """

        elt, _, _ = self._find(key)
        return elt

    def find(self, key):
        """ Find the element with the specified key """

        _, elt, _ = self._find(key)
        return elt

    def find_ge(self, key):
        """ Find the element greater or equal to the specified key """

        _, _, elt = self._find(key)
        return elt

    def find_gt(self, key):
        """ Find the element greater than the specified key """

        _, _, elt = self._find(key)
        return self.next(elt.Dereference()) if elt is not None else None

    def first(self):
        """ Returns the first element in the tree """

        return self._minmax(".rbe_left")

    def last(self):
        """ Returns the last element in the tree """

        return self._minmax(".rbe_right")

    def next(self, elt):
        """ Returns the next element in rbtree order or None """

        return self._sibling(elt, ".rbe_left", ".rbe_right")

    def prev(self, elt):
        """ Returns the next element in rbtree order or None """

        return self._sibling(elt, ".rbe_right", ".rbe_left")

    def iter(self, min_key=None, max_key=None):
        """
        Iterates all elements in this red-black tree
        with min_key <= key < max_key
        """

        e = self.first() if min_key is None else self.find_ge(min_key)

        if max_key is None:
            while e is not None:
                yield e
                e = self.next(e)
        else:
            cmp = self.cmp
            while e is not None and cmp(e, max_key) >= 0:
                yield e
                e = self.next(e)

    def __iter__(self):
        return self.iter()


def iter_RB_HEAD(rbh_root_value, link_field):
    """ Conveniency wrapper for RB_HEAD iteration """

    return RB_HEAD(rbh_root_value, link_field, None).iter()


def iter_smr_queue(head_value, elt_type, field_name_or_path):
    """
    Iterate over an SMR queue of entries (<kern/smr.h>)

    @param head_value (SBValue)
        a reference to the list head (struct smrq_*_head)

    @param elt_type (SBType)
        The type of the elements on the chain

    @param field_name_or_path (str)
        The name of (or path to if starting with '.') the field
        containing the struct mpsc_queue_chain linkage.
    """

    transform = elt_type.xContainerOfTransform(field_name_or_path)

    return (transform(e) for e in iter_linked_list(
        head_value, '.next.__smr_ptr', '.first.__smr_ptr'
    ))

class _Hash(object, metaclass=ABCMeta):
    @abstractproperty
    def buckets(self):
        """
        Returns the number of buckets in the hash table
        """
        pass

    @abstractproperty
    def count(self):
        """
        Returns the number of elements in the hash table
        """
        pass

    @abstractproperty
    def rehashing(self):
        """
        Returns whether the hash is currently rehashing
        """
        pass

    @abstractmethod
    def iter(self, detailed=False):
        """
        @param detailed (bool)
            whether to enumerate just elements, or show bucket info too
            when bucket info is requested, enumeration returns a tuple of:
            (0, bucket, index_in_bucket, element)
        """
        pass

    def __iter__(self):
        return self.iter()

    def describe(self):
        fmt = (
            "Hash table info\n"
            " address              : {1:#x}\n"
            " element count        : {0.count}\n"
            " bucket count         : {0.buckets}\n"
            " rehashing            : {0.rehashing}"
        )
        print(xnu_format(fmt, self, self.hash_value.GetLoadAddress()))

        if self.rehashing:
            print()
            return

        b_len = {}
        for _, b_idx, e_idx, _ in self.iter(detailed=True):
            b_len[b_idx] = e_idx + 1

        stats = {i: 0 for i in range(max(b_len.values()) + 1) }
        for v in b_len.values():
            stats[v] += 1
        stats[0] = self.buckets - len(b_len)

        fmt = (
            " histogram            :\n"
            "  {:>4}  {:>6}  {:>6}  {:>6}  {:>5}"
        )
        print(xnu_format(fmt, "size", "count", "(cum)", "%", "(cum)"))

        fmt = "  {:>4,d}  {:>6,d}  {:>6,d}  {:>6.1%}  {:>5.0%}"
        tot = 0
        for sz, n in stats.items():
            tot += n
            print(xnu_format(fmt, sz, n, tot, n / self.buckets, tot / self.buckets))


class SMRHash(_Hash):
    """
    Class providing utilities to manipulate SMR hash tables
    """

    def __init__(self, hash_value, traits_value):
        """
        Create an smr hash table iterator

        @param hash_value (SBValue)
            a reference to a struct smr_hash instance.

        @param traits_value (SBValue)
            a reference to the traits for this hash table
        """
        super().__init__()
        self.hash_value = hash_value
        self.traits_value = traits_value

    @property
    def buckets(self):
        hash_arr = self.hash_value.xGetScalarByName('smrh_array')
        return 1 << (64 - ((hash_arr >> 48) & 0x00ff))

    @property
    def count(self):
        return self.hash_value.xGetScalarByName('smrh_count')

    @property
    def rehashing(self):
        return self.hash_value.xGetScalarByName('smrh_resizing')

    def iter(self, detailed=False):
        obj_null = self.traits_value.chkGetChildMemberWithName('smrht_obj_type')
        obj_ty   = obj_null.GetType().GetArrayElementType().GetPointeeType()
        lnk_offs = self.traits_value.xGetScalarByPath('.smrht.link_offset')
        hash_arr = self.hash_value.xGetScalarByName('smrh_array')
        hash_sz  = 1 << (64 - ((hash_arr >> 48) & 0x00ff))
        hash_arr = obj_null.xCreateValueFromAddress(None,
            hash_arr | 0xffff000000000000, gettype('struct smrq_slist_head'));

        if detailed:
            return (
                (0, head_idx, e_idx, e.xCreateValueFromAddress(None, e.GetLoadAddress() - lnk_offs, obj_ty))
                for head_idx, head in enumerate(hash_arr.xIterSiblings(0, hash_sz))
                for e_idx, e in enumerate(iter_linked_list(head, '.next.__smr_ptr', '.first.__smr_ptr'))
            )

        return (
            e.xCreateValueFromAddress(None, e.GetLoadAddress() - lnk_offs, obj_ty)
            for head in hash_arr.xIterSiblings(0, hash_sz)
            for e in iter_linked_list(head, '.next.__smr_ptr', '.first.__smr_ptr')
        )


class SMRScalableHash(_Hash):

    def __init__(self, hash_value, traits_value):
        """
        Create an smr hash table iterator

        @param hash_value (SBValue)
            a reference to a struct smr_shash instance.

        @param traits_value (SBValue)
            a reference to the traits for this hash table
        """
        super().__init__()
        self.hash_value = hash_value
        self.traits_value = traits_value

    @property
    def buckets(self):
        shift = self.hash_value.xGetScalarByPath('.smrsh_state.curshift')
        return (0xffffffff >> shift) + 1;

    @property
    def count(self):
        sbv      = self.hash_value.chkGetChildMemberWithName('smrsh_count')
        addr     = sbv.GetValueAsAddress()
        target   = sbv.GetTarget()
        ncpus    = target.chkFindFirstGlobalVariable('zpercpu_early_count').xGetValueAsInteger()
        pg_shift = target.chkFindFirstGlobalVariable('page_shift').xGetValueAsInteger()

        return sum(
            target.xReadInt64(addr + (cpu << pg_shift))
            for cpu in range(ncpus)
        )

    @property
    def rehashing(self):
        curidx = self.hash_value.xGetScalarByPath('.smrsh_state.curidx');
        newidx = self.hash_value.xGetScalarByPath('.smrsh_state.newidx');
        return curidx != newidx

    def iter(self, detailed=False):
        """
        @param detailed (bool)
            whether to enumerate just elements, or show bucket info too
            when bucket info is requested, enumeration returns a tuple of:
            (table_index, bucket, index_in_bucket, element)
        """

        hash_value   = self.hash_value
        traits_value = self.traits_value

        obj_null = traits_value.chkGetChildMemberWithName('smrht_obj_type')
        obj_ty   = obj_null.GetType().GetArrayElementType().GetPointeeType()
        lnk_offs = traits_value.xGetScalarByPath('.smrht.link_offset')
        hashes   = []

        curidx   = hash_value.xGetScalarByPath('.smrsh_state.curidx');
        newidx   = hash_value.xGetScalarByPath('.smrsh_state.newidx');
        arrays   = hash_value.chkGetChildMemberWithName('smrsh_array')

        array    = arrays.chkGetChildAtIndex(curidx)
        shift    = hash_value.xGetScalarByPath('.smrsh_state.curshift')
        hashes.append((curidx, array.Dereference(), shift))
        if newidx != curidx:
            array    = arrays.chkGetChildAtIndex(newidx)
            shift    = hash_value.xGetScalarByPath('.smrsh_state.newshift')
            hashes.append((newidx, array.Dereference(), shift))

        seen = set()

        def _iter_smr_shash_bucket(head):
            addr  = head.xGetScalarByName('lck_ptr_bits')
            tg    = head.GetTarget()

            while addr & 1 == 0:
                addr &= 0xfffffffffffffffe
                e = head.xCreateValueFromAddress(None, addr - lnk_offs, obj_ty)
                if addr not in seen:
                    seen.add(addr)
                    yield e
                addr = tg.xReadULong(addr);

        if detailed:
            return (
                (hash_idx, head_idx, e_idx, e)
                for hash_idx, hash_arr, hash_shift in hashes
                for head_idx, head in enumerate(hash_arr.xIterSiblings(
                    0, 1 + (0xffffffff >> hash_shift)))
                for e_idx, e in enumerate(_iter_smr_shash_bucket(head))
            )

        return (
            e
            for hash_idx, hash_arr, hash_shift in hashes
            for head in hash_arr.xIterSiblings(
                0, 1 + (0xffffffff >> hash_shift))
            for e in _iter_smr_shash_bucket(head)
        )


__all__ = [
    iter_linked_list.__name__,
    iter_queue_entries.__name__,
    iter_queue.__name__,
    iter_circle_queue.__name__,

    iter_mpsc_queue.__name__,

    iter_priority_queue.__name__,

    iter_SLIST_HEAD.__name__,
    iter_LIST_HEAD.__name__,
    iter_STAILQ_HEAD.__name__,
    iter_TAILQ_HEAD.__name__,
    iter_SYS_QUEUE_HEAD.__name__,
    iter_RB_HEAD.__name__,
    RB_HEAD.__name__,

    iter_smr_queue.__name__,
    SMRHash.__name__,
    SMRScalableHash.__name__,
]
