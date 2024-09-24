XNU hibernation
===============

Suspending the entire system state to RAM.

Goal
----

This document discusses the design and implementation of XNU hibernation. The
reader is assumed to generally understand how standard suspend to RAM (S2R)
works in XNU; a detailed discussion of S2R is beyond the scope of this
discussion.

Vocabulary
----------

* Polled I/O : a mode of operation supported by I/O drivers (primarily storage
               devices) where operations may be conducted from a single-threaded
               context with interrupts disabled
* S2R        : Suspend to RAM (aka sleep)
* WKdm       : Wilson-Kaplan direct mapped compression

Background
----------

In order to prolong battery life, XNU supports suspending/powering off various
devices and preserving the state of those devices in memory. This feature is
referred to as suspend to RAM (S2R). In this mode, IOKit delivers a number of
notifications to IOServices to allow them to participate in S2R.

What is hibernation?
--------------------

Hibernation is a feature built on the foundation of S2R. However, while S2R
preserves state in memory (which must therefore remain powered), hibernation
preserves contents to persistent storage (the disk) and then completely powers
the system off.

Hibernation entry
-----------------

During hibernation, XNU invokes essentially the normal S2R machinery, but with a
few hibernation-specific differences:

* PMRootDomain calls `IOHibernateSystemSleep()` before system sleep (devices
  awake, normal execution context).
* `IOHibernateSystemSleep()` opens the hibernation file (or partition) at the
  BSD level, grabs its extents and searches for a polling driver willing to work
  with that IOMedia.
* The BSD code makes an ioctl to the storage driver to get the partition base
  offset to the disk, and other ioctls to get the transfer constraints.
* If successful, the file is written to make sure it's initially not bootable
  (in case of later failure) and the `boot-image` nvram variable is set to point
  to the first block of the file. (has to be done here because writing to nvram
  may block, so we have to do this before preemption is disabled).
* `hibernate_page_list_allocate()` is called to allocate page bitmaps for all
  DRAM.
  - The hibernation code represents every page of physical memory in page
    bitmaps of type `hibernate_bitmap_t`. There is one page bitmap per range of
    memory, with a bit to represent each page in that range; these page bitmaps
    are in turn stored in a `hibernate_page_list_t`. The page bitmaps are used
    to represent, for each page, whether preservation of that page is necessary.
  - On ARM64, `secure_hmac_get_io_ranges()` is called to get a list of the I/O
    regions that need to be included in the hibernation image (for example, the
    GPU UAT handoff region). These I/O regions are typically DRAM regions carved
    out by iBoot that exist outside of kernel-managed memory. A page bitmap is
    allocated for each one of these ranges (as well as a single bitmap for the
    kernel-managed DRAM memory).
* `hibernate_processor_setup()` is called to set up some platform-specific state
  needed in the hibernation image header. `hibernate_processor_setup()` also
  sets a flag in the boot processor's `cpu_data_t` to indicate that hibernation
  is in progress on this CPU.
* At this point, `gIOHibernateState` is set to the value
  `kIOHibernateStateHibernating`.
* Regular sleep progresses; some drivers may inspect the root domain property
  `kIOHibernateStateKey` to modify behavior. The platform drivers save state to
  memory as usual, but any drivers required for hibernation I/O are left in a
  state such that polled I/Os can be issued.
* By the time regular sleep has completed, all CPUs but the boot CPU have been
  halted, and we are running on the boot CPU's idle thread in the shutdown
  context, with preemption disabled.
* Eventually the platform calls `hibernate_write_image()` in the shutdown
  context on the last cpu, at which point memory is ready to be saved. This call
  is made from `acpi_hibernate()` on Intel and from `ml_arm_sleep()` on ARM64.
* `hibernate_write_image()` runs in the shutdown context, where no blocking is
  permitted because preemption is disabled. `hibernate_write_image()` calls
  `hibernate_page_list_setall()` to get the page bitmaps of DRAM that need to be
  saved.
* All pages are assumed to be saved (as part of the wired image) unless
  explicitly subtracted by `hibernate_page_list_setall()`.
  `hibernate_page_list_setall()` calls `hibernate_page_list_setall_machine()` to
  make platform-specific amendments to the page bitmaps.
* `hibernate_write_image()` writes the image header and extents list. The header
  includes the second file extent so that only the header block is needed to
  read the file, regardless of the underlying filesystem.
  - The extents list describes the file's layout on disk. This block list makes
    it possible for the platform booter to read the hibernation file from disk
    without having to understand the underlying filesystem.
* Some sections of memory are written directly (and uncompressed) to the image.
  These are the portions of XNU itself that are required during hibernation
  resume, as well as some other data that is required by the platform booter.
  - On Intel, the `__HIB` segment is written to the hibernation image.
  - On ARM64, because of ctrr/ktrr, a single `__HIB` segment isn't possible.
    Instead, a number of sections of the kernel are written:
    `__TEXT_EXEC,__hib_text`, `__DATA,__hib_data`, and
    `__DATA_CONST,__hib_const`. The `__PPL` segment is also stored to the image
    so that the PPL hmac driver can be used during hibernation resume. Certain
    other pieces of memory must also be written unmodified to the hibernation
    image for use by iBoot. Those pieces are described in the device tree so
    that XNU doesn't need to know the details.
    `secure_hmac_fetch_hibseg_and_info()` is used to determine the set of memory
    regions to be stored in this phase. This routine also calculates an HMAC
    that can be used by the booter to validate this content.
* The portions of XNU (code and data) that are stored directly to the
  hibernation image should be entirely self-contained; these are the only
  portions of XNU that are available during resume to decompress the image.
* Some additional pages are removed from the page bitmaps; these include various
  temporary buffers used for hibernation.
* The page bitmaps are written to the image.
* More areas are removed from the page bitmaps (after they have been written to
  the image); these include the pages already stored directly to the image, as
  well as the stack that hibernation resume will run on.
  `hibernate_page_list_set_volatile()` is invoked to make platform-specific
  amendments to the page bitmaps.
* Each wired page is compressed and written and then each non-wired page.
  Compression and disk writes can occur in parallel if the polled mode I/O
  driver supports this.
  - On ARM64, `secure_hmac_update_and_compress_page()` is called for each page
    included in the image so that the PPL can compute an HMAC of the hibernation
    payload.
* The image header records the values of `mach_absolute_time()` and
  `mach_continuous_time()` close to the end of `hibernate_write_image()`. These
  values can be used to fix up the offets applied to the hardware clock after
  hibernation exit.
* The image header is finalized.
  - On ARM64, `secure_hmac_final()` is called to compute the HMAC of the
    hibernation payload. There are actually two separate HMACs computed, one for
    the wired pages and one for the non-wired pages. These HMACs are stored in
    the image header.
  - On ARM64, `secure_hmac_fetch_rorgn_sha()` and `secure_hmac_fetch_rorgn_hmac()` are
    called to obtain the SHA256 and HMAC of the read-only region. They were
    calculated on cold boot. They are stored in the image header.
    This is described in more detail in the "Security details" section of this
    document.
  - On ARM64, `secure_hmac_finalize_image()` is called to compute the HMAC of the
    header of the image. This is described in more detail in the "Security
    details" section of this document.
* The image header is written to the start of the file and the polling driver
  closed.
* The machine powers down.
  - On Intel, depending on power settings, the system could sleep instead at
    this point. This allows for "safe sleep" where RAM remains powered until the
    user wakes the system or the battery dies.
  - On ARM64, we do not support this mode because hibernation is intended to
    only be invoked on a critical battery event.

Hibernation exit
----------------

* The platform booter sees the `boot-image` nvram variable containing the device
  and block number of the image, reads the header, and if the signature is
  correct proceeds. The `boot-image` variable is cleared.
  - On ARM64, iBoot takes the read-only region SHA256 value from the image
    header and calculates an HMAC. It then compares the HMAC against the
    value stored in the image header. If they do not match, iBoot panics.
* The platform booter reads the portion of the image used for wired pages, to
  memory. Its assumed this will fit in memory in its entirety. The image is
  decrypted (either transparently by ANS or in software, depending on platform
  support). The platform booter is not expected to decompress any of the
  payload; that is the kernel's responsibility.
* The platform booter copies the portions of XNU that were previously saved to
  the image back to their original physical addresses in memory.
* The platform booter invokes `hibernate_machine_entrypoint()`, passing in the
  location of the image in memory. Translation is off. Only code and data that
  was mapped by the booter is safe to call, since all the other wired pages are
  still compressed in the image.
  - On Intel, `hibernate_machine_entrypoint()` sets up a simple temporary page
    table; this page table will later be modified as necessary while pages are
    being restored.
  - On ARM64, `hibernate_machine_entrypoint()` sets up a temporary page table
    such that all of the required XNU code pages are executable, all data pages
    are readable/writable as necessary, and all of the rest of memory is mapped
    such that it can be written to during restore. Some device registers also
    have to be mapped to support serial logging and using the hmac block.
* Any pages occupied by the raw image are removed from from the page bitmaps.
  - On Intel, this is done in `hibernate_kernel_entrypoint()`.
  - On ARM64, we have to do this from `hibernate_machine_entrypoint()` because
    we borrow free pages (as indicated by the page bitmaps) to store the
    temporary page table.
* `hibernate_machine_entrypoint()` calls `hibernate_kernel_entrypoint()`.
* `hibernate_kernel_entrypoint()` uses the page bitmaps to determine which pages
  can be uncompressed from the wired image directly to their final location. Any
  pages that conflict with the image itself are copied to interim scratch space.
* After all of the image has been parsed, the pages that were temporarily copied
  to scratch are uncompressed to their final location, overwriting pages in the
  wired image.
  - `hibernate_restore_phys_page()` is used to actually copy pages to their
    final location.
* At this point, `gIOHibernateState` is set to
  `kIOHibernateStateWakingFromHibernate`.
* `pal_hib_patchup()` is called to perform platform-specific post-resume fixups
  - On Intel, `pal_hib_patchup()` is a no-op.
  - On ARM64, `pal_hib_patchup()` is responsible for validating the HMAC of the
    wired pages. `pal_hib_patchup()` also fixes up other state (such as some
    PPL-related context).
* After all of the wired pages have been restored, a wake from sleep is
  simulated.
  - On Intel, `hibernate_kernel_entrypoint()` calls `acpi_wake_prot_entry()`.
  - On ARM64, `hibernate_kernel_entrypoint()` returns to
    `hibernate_machine_entrypoint()`, which then jumps to `reset_vector`.
* The kernel proceeds on essentially a normal S2R wake, with some
  hibernation-specific changes.
  - On ARM64, an important difference is that a normal S2R wake on some
    platforms will run through the reconfig engine, whereas a hibernate wake
    cannot invoke the reconfig engine and must emulate some of the reconfig
    sequence on the AP.
  - On ARM64, some further fixup is done in `arm_init_cpu()`.
     + `wake_abstime` needs to be restored to the last absolute time captured
       during hibernation entry. This is necessary because during normal S2R,
       `wake_abstime` is captured too early; later calls to
       `mach_absolute_time()` in the hibernation entry path cause the
       `s_last_absolute_time` test to fail if we don't do this fixup.
     + `hwclock_conttime_offset` is set to the `hwClockOffset` value that iBoot
       computed. This is necessary since `ml_get_hwclock()` does not tick across
       hibernation but `mach_continuous_time()` is expected to.
     + The boot CPU's idle thread preemption_count also has to be fixed up. This
       is necessary because the page containing preemption_count is captured
       when the count is set to 1 (since the page is captured from within the
       PPL).
* After the platform CPU init code is called, `hibernate_machine_init()` is
  called to restore the rest of memory, using the polled mode driver, before
  other threads can run or any devices are turned on. This split of wired vs.
  non-wired pages reduces the memory usage for the platform booter, and allows
  decompression in parallel with disk reads for the non-wired pages.
* The polling driver is closed down and regular wake proceeds.
* When the kernel calls IOKit to wake (normal execution context)
  `hibernate_teardown()` is called to release any memory.
* The hibernation file is closed via BSD.

Hibernation file management
---------------------------

powerd in userspace is responsible for managing the lifecycle of the hibernation
file. The details of this lifecycle are beyond the scope of this document, but
essentially, it gets created and its space is preallocated by powerd the first
time the system hibernates. powerd can also grow the file as necessary.

Security details
----------------

### Intel:

* The hibernation image is encrypted with a key obtained from the APFS
  `APFSMEDIA_GETHIBERKEY` platform function.

### ARM64:

* The hibernation image is encrypted with a key obtained from the SEP. The
  details for how this key is derived and used are beyond the scope of this
  document, but are documented in detail in the AppleSEPOS project
  (doc/SecureHibernation).
* Various portions of the hibernation image have HMACs calculated over them. All
  HMACs are calculated by the PPL. The exact scheme for computing these HMACs is
  documented in more detail in ppl_hib.c, but the HMACs that are calculated are:
  - `imageHeaderHMAC` is an HMAC of the header of the image, up to
    `imageHeaderHMACSize`. However, because of the order that data is written
    (the header is the last thing actually written), the HMAC is actually
    calculated as `HMAC(SHA([data after header up to imageHeaderHMACSize],
    [header]))`.
  - `handoffHMAC` is an HMAC of the `IOHibernateHandoff` data passed from iBoot
    to XNU
  - `image1PagesHMAC` is an HMAC of the wired pages that were stored to the
    hibernation image
  - `image2PagesHMAC` is an HMAC of the non-wired pages that were stored to the
    hibernation image
* The PPL hibernation driver also keeps track of every PPL-owned page being
  hashed (both kernel-managed memory and I/O memory owned by the PPL). This will
  be double-checked in `secure_hmac_finalize_image()` to ensure that all PPL-owned
  memory is included in the hibernation image. Any missing pages will panic the
  system as the absence of PPL pages in the image could be a security risk (and
  surely a bug).
* During early boot, `secure_hmac_compute_rorgn_hmac()` is used to measure the
  entirety of the rorgn. On hibernation resume, the same function is invoked to
  verify that the rorgn matches its original contents.
  - Only the SHA256 of the rorgn is compared on resume. The SIO HMAC key1, used
    to compute this HMAC, is invalidated by iBoot on the resume path after it
    verifies the HMAC. See rdar://75750348 (xnu should store the SHA of the
    read-only region along with the hash in memory for iBoot to validate on
    hibernate resume).
