/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
 *
 * This file contains the low-level serial drivers used on ARM/ARM64 devices.
 * The generic serial console code in osfmk/console/serial_console.c will call
 * into this code to transmit and receive serial data.
 *
 * Logging can be performed on multiple serial interfaces at once through a
 * method called serial multiplexing. This is implemented by enumerating which
 * serial interfaces are available on boot and registering them into a linked
 * list of interfaces pointed to by gPESF. When outputting or receiving
 * characters, each interface is queried in turn.
 *
 * Please view doc/arm_serial.md for an in-depth description of these drivers.
 */
#include <kern/clock.h>
#include <kern/debug.h>
#include <libkern/OSBase.h>
#include <libkern/section_keywords.h>
#include <mach/mach_time.h>
#include <machine/atomic.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <pexpert/device_tree.h>
#include <pexpert/arm/consistent_debug.h>
#include <pexpert/arm64/board_config.h>
#include <arm64/proc_reg.h>
#include <pexpert/arm/protos.h>
#include <kern/sched_prim.h>
#ifdef PL011_UART
#include <pexpert/arm/pl011.h>
#endif /* PL011_UART */
#if HIBERNATION
#include <machine/pal_hibernate.h>
#endif /* HIBERNATION */

struct pe_serial_functions {
	/* Initialize the underlying serial hardware. */
	void (*init) (void);

	/* Return a non-zero value if the serial interface is ready to send more data. */
	unsigned int (*transmit_ready) (void);

	/* Write a single byte of data to serial. */
	void (*transmit_data) (uint8_t c);

	/* Return a non-zero value if there's a byte of data available. */
	unsigned int (*receive_ready) (void);

	/* Read a single byte from serial. */
	uint8_t (*receive_data) (void);

	/* Enables IRQs from this device. */
	void (*enable_irq) (void);

	/* Disables IRQs from this device and reports whether IRQs were enabled. */
	bool (*disable_irq) (void);

	/* Clears this device's IRQs targeting this agent, returning true if at least one IRQ was cleared. */
	bool (*acknowledge_irq) (void);

	/**
	 * Whether this serial driver can handle irqs. This value should be set by
	 * querying the device tree to see if the serial device has interrupts
	 * associated with it.
	 *
	 * For a device to support IRQs:
	 *   - enable_irq, disable_irq, and acknowledge_irq must be non-null
	 *   - The AppleSerialShim kext must be able to match to the serial device
	 *     in the IORegistry and call serial_enable_irq with the proper
	 *     serial_device_t
	 *   - The device tree entry for the serial device should have an interrupt
	 *     associated with it.
	 */
	bool has_irq;

	/* enum identifying which serial device these functions belong to. */
	serial_device_t device;

	/* Pointer to the next serial interface in the linked-list. */
	struct pe_serial_functions *next;
};

MARK_AS_HIBERNATE_DATA_CONST_LATE static struct pe_serial_functions* gPESF = NULL;

/**
 * Whether uart has been initialized already. This value is kept across a
 * sleep/wake cycle so we know we need to reinitialize when serial_init is
 * called again after wake.
 */
MARK_AS_HIBERNATE_DATA static bool uart_initted = false;

/* Whether uart should run in simple mode that works during hibernation resume. */
MARK_AS_HIBERNATE_DATA bool uart_hibernation = false;

/** Set <=> transmission is authorized.
 * Always set, unless SERIALMODE_ON_DEMAND is provided at boot,
 * and no data has yet been received.
 * Originaly meant to be a per-pe_serial_functions variable,
 * but the data protection on the structs prevents it. */
static bool serial_do_transmit = 1;

/**
 * Used to track if all IRQs have been initialized. Each bit of this variable
 * represents whether or not a serial device that reports supporting IRQs has
 * been initialized yet (1 -> not initialized, 0 -> initialized)
 */
static uint32_t serial_irq_status = 0;

/**
 * Set by the 'disable-uart-irq' boot-arg to force serial IRQs into polling mode
 * by preventing the serial driver shim kext from registering itself with
 * serial_enable_irq.
 */
static bool disable_uart_irq = 0;

static void
register_serial_functions(struct pe_serial_functions *fns)
{
	fns->next = gPESF;
	gPESF = fns;
}

/**
 * Indicates whether or not a given device's irqs have been set up by calling
 * serial_enable_irq for that particular device.
 *
 * @param device_fns Serial functions for the device that is being checked
 * @return Whether or not the irqs have been initialized for that device
 */
static bool
irq_initialized(struct pe_serial_functions *device_fns)
{
	return (serial_irq_status & device_fns->device) == 0;
}

/**
 * Indicates whether or not a given device supports irqs and if they are ready
 * to be used.
 *
 * @param device_fns Serial functions for the device that is being checked
 * @return Whether or not the device can and will send IRQs.
 */
static bool
irq_available_and_ready(struct pe_serial_functions *device_fns)
{
	return device_fns->has_irq && irq_initialized(device_fns);
}

/**
 * Searches through the global serial functions list and returns the serial function for a particular device
 *
 * @param device The device identifier to search for
 * @return Serial functions for the specified device
 */
static struct pe_serial_functions *
get_serial_functions(serial_device_t device)
{
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		if (fns->device == device) {
			return fns;
		}
		fns = fns->next;
	}
	return NULL;
}

/**
 * The action to take when polling and waiting for a serial device to be ready
 * for output. On ARM64, takes a WFE because the WFE timeout will wake us up in
 * the worst case. On ARMv7 devices, we need to hot poll.
 */
static inline void
serial_poll(void)
{
#if __arm64__
	if (!uart_hibernation) {
		__builtin_arm_wfe();
	}
#endif
}

/**
 * This ensures that if we have a future product that supports hibernation, but
 * doesn't support either UART serial or dock-channels, then hibernation will
 * gracefully fall back to the serial method that is supported.
 */
#if HIBERNATION || defined(APPLE_UART)
MARK_AS_HIBERNATE_DATA static volatile apple_uart_registers_t *apple_uart_registers = 0;
#endif /* HIBERNATION || defined(APPLE_UART) */

#if HIBERNATION || defined(DOCKCHANNEL_UART)
MARK_AS_HIBERNATE_DATA static vm_offset_t dockchannel_uart_base = 0;
#endif /* HIBERNATION || defined(DOCKCHANNEL_UART) */

#ifdef PL011_UART
static volatile pl011_registers_t *pl011_registers = NULL;
#endif /* PL011_UART */

/*****************************************************************************/

#ifdef APPLE_UART
static void apple_uart_set_baud_rate(uint32_t baud_rate);

/**
 * The Apple UART is configured to use 115200-8-N-1 communication.
 */
static void
apple_uart_init(void)
{
	ucon_t ucon = { .raw = 0 };
	// Use NCLK (which is constant) instead of PCLK (which is variable).
	ucon.clock_selection = UCON_CLOCK_SELECTION_NCLK;
	ucon.transmit_mode = UCON_TRANSMIT_MODE_INTERRUPT_OR_POLLING;
	ucon.receive_mode = UCON_RECEIVE_MODE_INTERRUPT_OR_POLLING;
	ml_io_write32((uintptr_t) &apple_uart_registers->ucon, ucon.raw);

	// Configure 8-N-1 communication.
	ulcon_t ulcon = { .raw = 0 };
	ulcon.word_length = ULCON_WORD_LENGTH_8_BITS;
	ulcon.parity_mode = ULCON_PARITY_MODE_NONE;
	ulcon.number_of_stop_bits = ULCON_STOP_BITS_1;
	ml_io_write32((uintptr_t) &apple_uart_registers->ulcon, ulcon.raw);

	apple_uart_set_baud_rate(115200);

	// Enable and reset FIFOs.
	ufcon_t ufcon = { .raw = 0 };
	ufcon.fifo_enable = 1;
	ufcon.tx_fifo_reset = 1;
	ufcon.rx_fifo_reset = 1;
	ml_io_write32((uintptr_t) &apple_uart_registers->ufcon, ufcon.raw);
}

static void
apple_uart_enable_irq(void)
{
	// Set the Tx FIFO interrupt trigger level to 0 bytes so interrupts occur when
	// the Tx FIFO is completely empty; this leads to higher Tx throughput.
	ufcon_t ufcon = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ufcon) };
	ufcon.tx_fifo_interrupt_trigger_level_dma_watermark = UFCON_TX_FIFO_ITL_0_BYTES;
	ml_io_write32((uintptr_t) &apple_uart_registers->ufcon, ufcon.raw);

	// Enable Tx interrupts.
	ucon_t ucon = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ucon) };
	ucon.transmit_interrupt = 1;
	ml_io_write32((uintptr_t) &apple_uart_registers->ucon, ucon.raw);
}

static bool
apple_uart_disable_irq(void)
{
	/* Disables Tx interrupts */
	ucon_t ucon = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ucon) };
	const bool irqs_were_enabled = ucon.transmit_interrupt;

	if (irqs_were_enabled) {
		ucon.transmit_interrupt = 0;
		ml_io_write32((uintptr_t) &apple_uart_registers->ucon, ucon.raw);
	}

	return irqs_were_enabled;
}

static bool
apple_uart_ack_irq(void)
{
	utrstat_t utrstat = { .raw = 0 };
	utrstat.transmit_interrupt_status = 1;
	ml_io_write32((uintptr_t) &apple_uart_registers->utrstat, utrstat.raw);
	return true;
}

static inline bool
apple_uart_fifo_is_empty(void)
{
	const ufstat_t ufstat = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ufstat) };
	return !(ufstat.tx_fifo_full || ufstat.tx_fifo_count);
}

static void
apple_uart_drain_fifo(void)
{
	while (!apple_uart_fifo_is_empty()) {
		serial_poll();
	}
}

static void
apple_uart_set_baud_rate(uint32_t baud_rate)
{
	// Maximum error tolerated from the target baud rate (measured in percentage
	// points). Anything greater than this will trigger a kernel panic because
	// UART communication will not be reliable.
	const float kMaxErrorPercentage = 2.75;

	// The acceptable sample rate range; higher sample rates are typically more
	// desirable because you can more quickly detect the start bit.
	const int kMinSampleRate = 10;
	const int kMaxSampleRate = 16;

	// Find the first configuration that achieves the target baud rate accuracy,
	// starting with the highest sample rate.
	const float kSourceClock = gPEClockFrequencyInfo.fix_frequency_hz;
	int ubr_div = 0;
	int sample_rate = 0;
	bool found_configuration = false;
	for (int _sample_rate = kMaxSampleRate; _sample_rate >= kMinSampleRate; _sample_rate--) {
		const float ideal_ubr_div = (kSourceClock / (baud_rate * _sample_rate)) - 1;
		if ((ideal_ubr_div - (int)ideal_ubr_div) < 0.00001f) {
			// The ideal baud rate divisor is (basically) attainable.
			ubr_div = (int)ideal_ubr_div;
			sample_rate = _sample_rate;
			found_configuration = true;
			break;
		} else {
			// The ideal baud rate divisor is not attainable; try rounding.
			const int ubr_div_rounded_down = (int)ideal_ubr_div;
			const int ubr_div_rounded_up = ubr_div_rounded_down + 1;
			const float higher_baud_rate = kSourceClock / ((ubr_div_rounded_down + 1) * _sample_rate);
			const float lower_baud_rate = kSourceClock / ((ubr_div_rounded_up + 1) * _sample_rate);
			if ((((higher_baud_rate - baud_rate) / baud_rate) * 100) < kMaxErrorPercentage) {
				ubr_div = ubr_div_rounded_down;
				sample_rate = _sample_rate;
				found_configuration = true;
				break;
			}
			if ((((baud_rate - lower_baud_rate) / baud_rate) * 100) < kMaxErrorPercentage) {
				ubr_div = ubr_div_rounded_up;
				sample_rate = _sample_rate;
				found_configuration = true;
				break;
			}
		}
	}

	if (!found_configuration) {
		panic("Unable to find a configuration for the UART that would result in a nominal baud rate close enough to %u", baud_rate);
	}

	// Found an acceptable configuration; write this to the register.
	ubrdiv_t ubrdiv = { .raw = 0 };
	ubrdiv.sample_rate = 16 - sample_rate;
	assert((0 <= ubr_div) && (ubr_div <= UINT16_MAX));
	ubrdiv.ubr_div = ubr_div;
	ml_io_write32((uintptr_t) &apple_uart_registers->ubrdiv, ubrdiv.raw);
}

MARK_AS_HIBERNATE_TEXT static unsigned int
apple_uart_transmit_ready(void)
{
	ufstat_t ufstat = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ufstat) };
	return !ufstat.tx_fifo_full;
}

MARK_AS_HIBERNATE_TEXT static void
apple_uart_transmit_data(uint8_t c)
{
	utxh_t utxh = { .txdata = c };
	ml_io_write32((uintptr_t) &apple_uart_registers->utxh, utxh.raw);
}

static unsigned int
apple_uart_receive_ready(void)
{
	ufstat_t ufstat = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->ufstat) };
	return ufstat.rx_fifo_full || ufstat.rx_fifo_count;
}

static uint8_t
apple_uart_receive_data(void)
{
	urxh_t urxh = { .raw = ml_io_read32((uintptr_t) &apple_uart_registers->urxh) };
	return urxh.rxdata;
}

MARK_AS_HIBERNATE_DATA_CONST_LATE
static struct pe_serial_functions apple_serial_functions =
{
	.init = apple_uart_init,
	.transmit_ready = apple_uart_transmit_ready,
	.transmit_data = apple_uart_transmit_data,
	.receive_ready = apple_uart_receive_ready,
	.receive_data = apple_uart_receive_data,
	.enable_irq = apple_uart_enable_irq,
	.disable_irq = apple_uart_disable_irq,
	.acknowledge_irq = apple_uart_ack_irq,
	.device = SERIAL_APPLE_UART
};

static void
apple_uart_setup(const DeviceTreeNode *const devicetree_node)
{
	// Get the physical address range of the Apple UART register block.
	const struct {
		uint64_t block_offset; // TODO: make this scale with #address-cells
		uint64_t block_size; // TODO: make this scale with #size-cells
	} *reg;
	unsigned int reg_size;
	if (SecureDTGetProperty(devicetree_node, "reg", (const void **)&reg, &reg_size) != kSuccess) {
		panic("Unable to find the 'reg' property on the Apple UART devicetree node");
	}
	assert(reg_size == sizeof(*reg));

	// Create a virtual mapping to that physical address range.
	const vm_offset_t soc_base_phys = pe_arm_get_soc_base_phys();
	apple_uart_registers = (apple_uart_registers_t *)ml_io_map(soc_base_phys + reg->block_offset, reg->block_size);

	// Check if interrupts are supported.
	const void *unused;
	unsigned int unused_size;
	if (SecureDTGetProperty(devicetree_node, "interrupts", &unused, &unused_size) == kSuccess) {
		apple_serial_functions.has_irq = true;
	}

	// Register the Apple UART serial driver.
	register_serial_functions(&apple_serial_functions);
}

#endif /* APPLE_UART */

/*****************************************************************************/

#ifdef DOCKCHANNEL_UART
#define DOCKCHANNEL_WR_MAX_STALL_US (30*1000)

static vm_offset_t      dock_agent_base;
static uint32_t         max_dockchannel_drain_period;
static uint64_t         dockchannel_drain_deadline;  // Deadline for external agent to drain before a software drain occurs
static bool             use_sw_drain;
static uint32_t         dock_wstat_mask;
static uint64_t         prev_dockchannel_spaces;        // Previous w_stat level of the DockChannel.
static uint64_t         dockchannel_stall_grace;
MARK_AS_HIBERNATE_DATA static bool     use_sw_drain;
MARK_AS_HIBERNATE_DATA static uint32_t dock_wstat_mask;

// forward reference
static struct pe_serial_functions dockchannel_serial_functions;

//=======================
// Local funtions
//=======================

static void
dockchannel_setup(const DeviceTreeNode *const devicetree_node)
{
	// Get the physical address ranges of the Dock Channels register blocks.
	const struct {
		uint64_t channels_block_offset; // TODO: make this scale with #address-cells
		uint64_t channels_block_size; // TODO: make this scale with #size-cells
		uint64_t agents_block_offset; // TODO: make this scale with #address-cells
		uint64_t agents_block_size; // TODO: make this scale with #size-cells
	} *reg;
	unsigned int reg_size;
	if (SecureDTGetProperty(devicetree_node, "reg", (const void **)&reg, &reg_size) != kSuccess) {
		panic("Unable to find the 'reg' property on the Dock Channels devicetree node");
	}
	assert(reg_size == sizeof(*reg));

	// Create virtual mappings for those physical address rangess.
	const vm_offset_t soc_base_phys = pe_arm_get_soc_base_phys();
	dockchannel_uart_base = ml_io_map(soc_base_phys + reg->channels_block_offset, reg->channels_block_size);
	dock_agent_base = ml_io_map(soc_base_phys + reg->agents_block_offset, reg->agents_block_size);

	// Configure various Dock Channels settings.
	const uint32_t *max_aop_clk;
	unsigned int max_aop_clk_size;
	if (SecureDTGetProperty(devicetree_node, "max-aop-clk", (const void **)&max_aop_clk, &max_aop_clk_size) == kSuccess) {
		assert(max_aop_clk_size == sizeof(*max_aop_clk));
		max_dockchannel_drain_period = (uint32_t)(*max_aop_clk * 0.03);
	} else {
		max_dockchannel_drain_period = (uint32_t)DOCKCHANNEL_DRAIN_PERIOD;
	}
	const uint32_t *enable_sw_drain;
	unsigned int enable_sw_drain_size;
	if (SecureDTGetProperty(devicetree_node, "enable-sw-drain", (const void **)&enable_sw_drain, &enable_sw_drain_size) == kSuccess) {
		assert(enable_sw_drain_size == sizeof(*enable_sw_drain));
		use_sw_drain = *enable_sw_drain;
	} else {
		use_sw_drain = 0;
	}
	const uint32_t *_dock_wstat_mask;
	unsigned int dock_wstat_mask_size;
	if (SecureDTGetProperty(devicetree_node, "dock-wstat-mask", (const void **)&_dock_wstat_mask, &dock_wstat_mask_size) == kSuccess) {
		assert(dock_wstat_mask_size == sizeof(*_dock_wstat_mask));
		dock_wstat_mask = *_dock_wstat_mask;
	} else {
		dock_wstat_mask = 0x1ff;
	}
	const void *unused;
	unsigned int unused_size;
	if (SecureDTGetProperty(devicetree_node, "interrupts", &unused, &unused_size) == kSuccess) {
		dockchannel_serial_functions.has_irq = true;
	}
	prev_dockchannel_spaces = rDOCKCHANNELS_DEV_WSTAT(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL) & dock_wstat_mask;
	dockchannel_drain_deadline = mach_absolute_time() + dockchannel_stall_grace;

	// Register the Dock Channels serial driver.
	register_serial_functions(&dockchannel_serial_functions);
}

static int
dockchannel_drain_on_stall()
{
	// Called when DockChannel runs out of spaces.
	// Check if the DockChannel reader has stalled. If so, empty the DockChannel ourselves.
	// Return number of bytes drained.

	if (mach_absolute_time() >= dockchannel_drain_deadline) {
		// It's been more than DOCKCHANEL_WR_MAX_STALL_US and nobody read from the FIFO
		// Drop a character.
		(void)ml_io_read32(rDOCKCHANNELS_DOCK_RDATA1(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL));
		os_atomic_inc(&prev_dockchannel_spaces, relaxed);
		return 1;
	}
	return 0;
}

static void
dockchannel_clear_intr(void)
{
	ml_io_write32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base),
	    ml_io_read32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base)) & ~(0x3));
	ml_io_write32(rDOCKCHANNELS_AGENT_AP_INTR_STATUS(dock_agent_base),
	    ml_io_read32(rDOCKCHANNELS_AGENT_AP_INTR_STATUS(dock_agent_base)) | 0x3);
	ml_io_write32(rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL(dock_agent_base),
	    ml_io_read32(rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL(dock_agent_base)) & ~(0x3));
	ml_io_write32(rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS(dock_agent_base),
	    ml_io_read32(rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS(dock_agent_base)) | 0x3);
}

static bool
dockchannel_disable_irq(void)
{
	const uint32_t ap_intr_ctrl = ml_io_read32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base));
	const bool irqs_were_enabled = ap_intr_ctrl & 0x1;
	if (irqs_were_enabled) {
		ml_io_write32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base), ap_intr_ctrl & ~(0x1));
	}
	return irqs_were_enabled;
}

static void
dockchannel_enable_irq(void)
{
	// set interrupt to be when fifo has 255 empty
	ml_io_write32(rDOCKCHANNELS_DEV_WR_WATERMARK(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL), 0xFF);
	ml_io_write32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base),
	    ml_io_read32(rDOCKCHANNELS_AGENT_AP_INTR_CTRL(dock_agent_base)) | 0x1);
}

static bool
dockchannel_ack_irq(void)
{
	/* First check if the IRQ is for the kernel */
	const uint32_t ap_intr_status = 0x1 & ml_io_read32(rDOCKCHANNELS_AGENT_AP_INTR_STATUS(dock_agent_base));
	if (0x1 == ap_intr_status) {
		/* And clear it */
		ml_io_write32(rDOCKCHANNELS_AGENT_AP_INTR_STATUS(dock_agent_base), ap_intr_status);
		return true;
	}
	return false;
}

MARK_AS_HIBERNATE_TEXT static void
dockchannel_transmit_data(uint8_t c)
{
	ml_io_write32(rDOCKCHANNELS_DEV_WDATA1(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL), (unsigned)c);

	if (use_sw_drain && !uart_hibernation) {
		os_atomic_dec(&prev_dockchannel_spaces, relaxed); // After writing a byte we have one fewer space than previously expected.
	}
}

static unsigned int
dockchannel_receive_ready(void)
{
	return ml_io_read32(rDOCKCHANNELS_DEV_RDATA0(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL)) & 0x7f;
}

static uint8_t
dockchannel_receive_data(void)
{
	return (uint8_t)((ml_io_read32(rDOCKCHANNELS_DEV_RDATA1(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL)) >> 8) & 0xff);
}

MARK_AS_HIBERNATE_TEXT static unsigned int
dockchannel_transmit_ready(void)
{
	uint32_t spaces = ml_io_read32(rDOCKCHANNELS_DEV_WSTAT(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL)) & dock_wstat_mask;

	if (!uart_hibernation) {
		if (use_sw_drain) {
			if (spaces > prev_dockchannel_spaces) {
				// More spaces showed up. That can only mean someone read the FIFO.
				// Note that if the DockFIFO is empty we cannot tell if someone is listening,
				// we can only give them the benefit of the doubt.
				dockchannel_drain_deadline = mach_absolute_time() + dockchannel_stall_grace;
			}
			prev_dockchannel_spaces = spaces;
			return spaces || dockchannel_drain_on_stall();
		}
	}

	return spaces;
}

static void
dockchannel_init(void)
{
	if (use_sw_drain) {
		nanoseconds_to_absolutetime(DOCKCHANNEL_WR_MAX_STALL_US * NSEC_PER_USEC, &dockchannel_stall_grace);
	}

	// Clear all interrupt enable and status bits
	dockchannel_clear_intr();

	// Setup DRAIN timer
	ml_io_write32(rDOCKCHANNELS_DEV_DRAIN_CFG(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL), max_dockchannel_drain_period);

	// Drain timer doesn't get loaded with value from drain period register if fifo
	// is already full. Drop a character from the fifo.
	(void)ml_io_read32(rDOCKCHANNELS_DOCK_RDATA1(dockchannel_uart_base, DOCKCHANNEL_UART_CHANNEL));
}

MARK_AS_HIBERNATE_DATA_CONST_LATE
static struct pe_serial_functions dockchannel_serial_functions =
{
	.init = dockchannel_init,
	.transmit_ready = dockchannel_transmit_ready,
	.transmit_data = dockchannel_transmit_data,
	.receive_ready = dockchannel_receive_ready,
	.receive_data = dockchannel_receive_data,
	.enable_irq = dockchannel_enable_irq,
	.disable_irq = dockchannel_disable_irq,
	.acknowledge_irq = dockchannel_ack_irq,
	.device = SERIAL_DOCKCHANNEL
};

#endif /* DOCKCHANNEL_UART */

/*****************************************************************************/

#ifdef PL011_UART

static unsigned int
pl011_uart_transmit_ready(void)
{
	const uartfr_t uartfr = { .raw = pl011_registers->uartfr.raw };
	return uartfr.txff != 1;
}

static void
pl011_uart_transmit_data(uint8_t c)
{
	uartdr_t uartdr = { .data = c };
	pl011_registers->uartdr.raw = uartdr.raw;
}

static unsigned int
pl011_uart_receive_ready(void)
{
	const uartfr_t uartfr = { .raw = pl011_registers->uartfr.raw };
	return uartfr.rxfe != 1;
}

static uint8_t
pl011_uart_receive_data(void)
{
	const uartdr_t uartdr = { .raw = pl011_registers->uartdr.raw };
	return uartdr.data;
}

static void
pl011_uart_init(void)
{
	// Before programming the control registers, we must first disable the UART.
	// We can accomplish this by manually resetting the UARTCR register.
	uartcr_t uartcr = { .raw = 0 };
	uartcr.rxe = 1; // This bit's reset value is 1.
	uartcr.txe = 1; // This bit's reset value is 1.
	pl011_registers->uartcr.raw = uartcr.raw;

	// Configure 8-N-1 communication and enable FIFOs.
	uartlcr_h_t uartlcr_h = { .raw = 0 };
	uartlcr_h.brk = 0;
	uartlcr_h.pen = 0;
	uartlcr_h.stp2 = 0;
	uartlcr_h.fen = 1;
	uartlcr_h.wlen = 0b11;
	pl011_registers->uartlcr_h.raw = uartlcr_h.raw;

	// Re-enable the UART.
	uartcr.uarten = 1;
	pl011_registers->uartcr.raw = uartcr.raw;
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) pl011_uart_serial_functions =
{
	.init = pl011_uart_init,
	.transmit_ready = pl011_uart_transmit_ready,
	.transmit_data = pl011_uart_transmit_data,
	.receive_ready = pl011_uart_receive_ready,
	.receive_data = pl011_uart_receive_data,
	.device = SERIAL_PL011_UART
};

static void
pl011_uart_setup(const DeviceTreeNode *const devicetree_node)
{
	// Get the physical address range of the PL011 UART register block.
	const struct {
		uint64_t block_offset; // TODO: make this scale with #address-cells
		uint64_t block_size; // TODO: make this scale with #size-cells
	} *reg;
	unsigned int reg_size;
	if (SecureDTGetProperty(devicetree_node, "reg", (const void **)&reg, &reg_size) != kSuccess) {
		panic("Unable to find the 'reg' property on the PL011 UART devicetree node");
	}
	assert(reg_size == sizeof(*reg));

	// Create a virtual mapping to that physical address range.
	const vm_offset_t soc_base_phys = pe_arm_get_soc_base_phys();
	pl011_registers = (pl011_registers_t *)ml_io_map(soc_base_phys + reg->block_offset, reg->block_size);

	// Register the PL011 UART serial driver.
	register_serial_functions(&pl011_uart_serial_functions);
}

#endif /* PL011_UART */

/*****************************************************************************/

/**
 * Output @str onto every registered serial interface by polling.
 *
 * @param str The string to output.
 */
static void uart_puts_force_poll(
	const char *str);

/**
 * Output @str onto a specific serial interface by polling.
 *
 * @param str The string to output.
 * @param fns The functions to use to output the message.
 */
static void uart_puts_force_poll_device(
	const char *str,
	struct pe_serial_functions *fns);

#if HIBERNATION
/**
 * Transitions the serial driver into a mode that can be run in the hibernation
 * resume context. In this mode, the serial driver runs at a barebones level
 * without making sure the serial devices are properly initialized or utilizing
 * features such as the software drain timer for dockchannels.
 *
 * Upon the next call to serial_init (once the hibernation image has been
 * loaded), this mode is exited and we return to the normal operation of the
 * driver.
 */
MARK_AS_HIBERNATE_TEXT void
serial_hibernation_init(void)
{
	uart_hibernation = true;
#if defined(APPLE_UART)
	apple_uart_registers = (apple_uart_registers_t *)gHibernateGlobals.hibUartRegPhysBase;
#endif /* defined(APPLE_UART) */
#if defined(DOCKCHANNEL_UART)
	dockchannel_uart_base = gHibernateGlobals.dockChannelRegPhysBase;
#endif /* defined(DOCKCHANNEL_UART) */
}

/**
 * Transitions the serial driver back to non-hibernation mode so it can resume
 * normal operations. Should only be called from serial_init on a hibernation
 * resume.
 */
MARK_AS_HIBERNATE_TEXT static void
serial_hibernation_cleanup(void)
{
	uart_hibernation = false;
#if defined(APPLE_UART)
	apple_uart_registers = (apple_uart_registers_t *)gHibernateGlobals.hibUartRegVirtBase;
#endif /* defined(APPLE_UART) */
#if defined(DOCKCHANNEL_UART)
	dockchannel_uart_base = gHibernateGlobals.dockChannelRegVirtBase;
#endif /* defined(DOCKCHANNEL_UART) */
}
#endif /* HIBERNATION */

/**
 * @brief This array maps "compatible" strings from the devicetree identifying
 * different serial device drivers to their corresponding setup functions.
 */
static const struct {
	const char *const compatible;
	void(*const setup)(const DeviceTreeNode * const devicetree_node);
} driver_setup_functions[] = {
#ifdef APPLE_UART
	{ .compatible = "uart-1,samsung", .setup = apple_uart_setup },
#endif // APPLE_UART
#ifdef DOCKCHANNEL_UART
	{ .compatible = "aapl,dock-channels", .setup = dockchannel_setup },
#endif // DOCKCHANNEL_UART
#ifdef PL011_UART
	{ .compatible = "arm,pl011", .setup = pl011_uart_setup },
#endif // PL011_UART
};

/**
 * Gets the phandle of the devicetree node that represents the serial device
 * XNU has been configured (either via devicetree or bootarg) to use.
 *
 * @param[out] phandle If XNU has been configured with a serial device to use,
 * then this function will populate this output parameter with a phandle.
 *
 * @return Whether XNU has been configured with a serial device to use. Also,
 * whether @p phandle has been populated by this function.
 */
static bool
get_serial_device_phandle(uint32_t * const phandle)
{
	// Check the "defaults" devicetree node to see whether or not a serial
	// device was specified. Specifically, check for the presence of a
	// "serial-device" phandle property.
	const DeviceTreeNode *defaults_node;
	if (SecureDTFindNodeWithStringProperty("name", "defaults", &defaults_node) != kSuccess) {
		panic("Unable to find the 'defaults' devicetree node.");
	}
	bool serial_device_phandle_specified = false;
	const uint32_t *defaults_phandle;
	unsigned int defaults_phandle_size;
	if (SecureDTGetProperty(defaults_node, "serial-device", (const void **)&defaults_phandle, &defaults_phandle_size) == kSuccess) {
		assert(defaults_phandle_size == sizeof(*defaults_phandle));
		*phandle = *defaults_phandle;
		serial_device_phandle_specified = true;
	}

	// Allow people to manually specify a serial device phandle via bootarg.
	uint32_t phandle_bootarg;
	if (PE_parse_boot_argn("serial-device", &phandle_bootarg, sizeof(phandle_bootarg))) {
		*phandle = phandle_bootarg;
		serial_device_phandle_specified = true;
	}

	// Give people an easier way to specify a serial device via bootarg (i.e.,
	// by giving the name of the devicetree node).
	const int kSerialDeviceNameMaxLen = 31;
	char serial_device_name_buffer[kSerialDeviceNameMaxLen + 1];
	if (PE_parse_boot_arg_str("serial-device-name", serial_device_name_buffer, sizeof(serial_device_name_buffer))) {
		// Find the devicetree node with that name.
		const DeviceTreeNode *serial_device_node;
		if (SecureDTFindNodeWithStringProperty("name", serial_device_name_buffer, &serial_device_node) != kSuccess) {
			panic("Unable to find a devicetree node with the name '%s'.", serial_device_name_buffer);
		}

		// Get the phandle of that node.
		const uint32_t *node_phandle;
		unsigned int node_phandle_size;
		if (SecureDTGetProperty(serial_device_node, "AAPL,phandle", (const void **)&node_phandle, &node_phandle_size) != kSuccess) {
			panic("The devicetree node has no phandle. This should never happen!");
		}
		assert(node_phandle_size == sizeof(*node_phandle));
		*phandle = *node_phandle;
		serial_device_phandle_specified = true;
	}

	return serial_device_phandle_specified;
}

int
serial_init(void)
{
	vm_offset_t     soc_base;

	struct pe_serial_functions *fns = gPESF;

	/**
	 * Even if the serial devices have already been initialized on cold boot,
	 * when coming out of a sleep/wake, they'll need to be re-initialized. Since
	 * the uart_initted value is kept across a sleep/wake, always re-initialize
	 * to be safe.
	 */
	if (uart_initted) {
#if HIBERNATION
		if (uart_hibernation) {
			serial_hibernation_cleanup();
		}
#endif /* HIBERNATION */
		while (fns != NULL) {
			fns->init();
			fns = fns->next;
		}

		return gPESF != NULL;
	}

	soc_base = pe_arm_get_soc_base_phys();

	if (soc_base == 0) {
		uart_initted = true;
		return 0;
	}

	PE_parse_boot_argn("disable-uart-irq", &disable_uart_irq, sizeof(disable_uart_irq));

	// Get the phandle of the serial device XNU has been configured to use.
	uint32_t phandle;
	if (!get_serial_device_phandle(&phandle)) {
		// XNU has not been configured to use a serial device; return early.
		return 0;
	}

	// Look at the "compatible" string in the devicetree node referenced by the
	// "serial-device" phandle property to see which driver we should use.
	const DeviceTreeNode *serial_device_node;
	if (SecureDTFindNodeWithPhandle(phandle, &serial_device_node) != kSuccess) {
		panic("Unable to find a devicetree node with phandle %x", phandle);
	}
	const char *compatible;
	unsigned int compatible_size;
	if (SecureDTGetProperty(serial_device_node, "compatible", (const void **)&compatible, &compatible_size) != kSuccess) {
		panic("The serial device devicetree node doesn't have a 'compatible' string");
	}

	// Call the setup function for the identified serial device driver.
	bool found_matching_driver = false;
	const int n_drivers = sizeof(driver_setup_functions) / sizeof(driver_setup_functions[0]);
	for (int i = 0; i < n_drivers; i++) {
		if (strcmp(compatible, driver_setup_functions[i].compatible) == 0) {
			found_matching_driver = true;
			driver_setup_functions[i].setup(serial_device_node);
		}
	}
	if (!found_matching_driver) {
		panic("Unable to find serial device driver for '%s'", compatible);
	}

	fns = gPESF;
	while (fns != NULL) {
		serial_do_transmit = 1;
		fns->init();
		if (fns->has_irq) {
			serial_irq_status |= fns->device; // serial_device_t is one-hot
		}
		fns = fns->next;
	}

#if HIBERNATION
	/* hibernation needs to know the UART register addresses since it can't directly use this serial driver */
	if (dockchannel_uart_base) {
		gHibernateGlobals.dockChannelRegPhysBase = ml_vtophys(dockchannel_uart_base);
		gHibernateGlobals.dockChannelRegVirtBase = dockchannel_uart_base;
		gHibernateGlobals.dockChannelWstatMask = dock_wstat_mask;
	}
	if (apple_uart_registers) {
		gHibernateGlobals.hibUartRegPhysBase = ml_vtophys((vm_offset_t)apple_uart_registers);
		gHibernateGlobals.hibUartRegVirtBase = (vm_offset_t)apple_uart_registers;
	}
#endif /* HIBERNATION */

	/* Complete. */
	uart_initted = true;
	return gPESF != NULL;
}

/**
 * Forbid or allow transmission over each serial until they receive data.
 */
void
serial_set_on_demand(bool on_demand)
{
	/* Enable or disable transmission. */
	serial_do_transmit = !on_demand;

	/* If on-demand is enabled, report it. */
	if (on_demand) {
		uart_puts_force_poll(
			"On-demand serial mode selected.\n"
			"Waiting for user input to send logs.\n"
			);
	}
}

/**
 * Returns a deadline for the longest time the serial driver should wait for an
 * interrupt for. This serves as a timeout for the IRQ to allow for the software
 * drain timer that dockchannels supports.
 *
 * @param fns serial functions representing the device to find the deadline for
 *
 * @returns absolutetime deadline for this device's IRQ.
 */
static uint64_t
serial_interrupt_deadline(__unused struct pe_serial_functions *fns)
{
#if defined(DOCKCHANNEL_UART)
	if (fns->device == SERIAL_DOCKCHANNEL && use_sw_drain) {
		return dockchannel_drain_deadline;
	}
#endif

	/**
	 *  Default to 1.5ms for all other devices. 1.5ms was chosen as the baudrate
	 * of the AppleSerialDevice is 115200, meaning that it should only take
	 * ~1.5ms to drain the 16 character buffer completely.
	 */
	uint64_t timeout_interval;
	nanoseconds_to_absolutetime(1500 * NSEC_PER_USEC, &timeout_interval);
	return mach_absolute_time() + timeout_interval;
}

/**
 * Goes to sleep waiting for an interrupt from a specificed serial device.
 *
 * @param fns serial functions representing the device to wait for
 */
static void
serial_wait_for_interrupt(struct pe_serial_functions *fns)
{
	/**
	 * This block of code is set up to avoid a race condition in which the IRQ
	 * is transmitted and processed by IOKit in between the time we check if the
	 * device is ready to transmit and when we call thread_block. If the IRQ
	 * fires in that time, thread_wakeup may have already been called in which
	 * case we would be blocking and have nothing to wake us up.
	 *
	 * To avoid this issue, we first call assert_wait_deadline, which prepares
	 * the thread to be blocked, but does not actually block the thread. After
	 * this point, any call to thread_wakeup from IRQ handler will prevent
	 * thread_block from actually blocking. As a performance optimization, we
	 * then double check if the device is ready to transmit and if it is, then
	 * we cancel the wait and just continue normally.
	 */
	assert_wait_deadline(fns, THREAD_UNINT, serial_interrupt_deadline(fns));
	if (!fns->transmit_ready()) {
		fns->enable_irq();
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		clear_wait(current_thread(), THREAD_AWAKENED);
	}
}

/**
 * Transmit a character over the specified serial output device.
 *
 * @param c Character to send
 * @param poll Whether we should poll or wait for an interrupt.
 * @param force Whether we should force this over the device if output has not been enabled yet.
 * @param fns Functions for the device to output over.
 */
static inline void
uart_putc_device(char c, bool poll, bool force, struct pe_serial_functions *fns)
{
	if (!(serial_do_transmit || force)) {
		return;
	}

	while (!fns->transmit_ready()) {
		if (irq_available_and_ready(fns) && !poll) {
			serial_wait_for_interrupt(fns);
		} else {
			serial_poll();
		}
	}
	fns->transmit_data((uint8_t)c);
}

/**
 * Output a character onto every registered serial interface whose
 * transmission is enabled..
 *
 * @param c The character to output.
 * @param poll Whether the driver should poll to send the character or if it can
 *             wait for an interrupt
 */
MARK_AS_HIBERNATE_TEXT void
uart_putc_options(char c, bool poll)
{
	struct pe_serial_functions *fns = gPESF;

	while (fns != NULL) {
		uart_putc_device(c, poll, false, fns);
		fns = fns->next;
	}
}

/**
 * Output a character onto every registered serial interface whose
 * transmission is enabled by polling.
 *
 * @param c The character to output.
 */
void
uart_putc(char c)
{
	uart_putc_options(c, true);
}

/**
 * Output @str onto every registered serial interface by polling.
 *
 * @param str The string to output.
 */
static void
uart_puts_force_poll(
	const char *str)
{
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		uart_puts_force_poll_device(str, fns);
		fns = fns->next;
	}
}

/**
 * Output @str onto a specific serial interface by polling.
 *
 * @param str The string to output.
 * @param fns The functions to use to output the message.
 */
static void
uart_puts_force_poll_device(
	const char *str,
	struct pe_serial_functions *fns)
{
	char c;
	while ((c = *(str++))) {
		uart_putc_device(c, true, true, fns);
	}
}

/**
 * Read a character from the first registered serial interface that has data
 * available.
 *
 * @return The character if any interfaces have data available, otherwise -1.
 */
int
uart_getc(void)
{
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		if (fns->receive_ready()) {
			serial_do_transmit = 1;
			return (int)fns->receive_data();
		}
		fns = fns->next;
	}
	return -1;
}

/**
 * Enables IRQs for a specific serial device and returns whether or not IRQs for
 * that device where enabled successfully. For a serial driver to have irqs
 * enabled, it must have the enable_irq, disable_irq, and acknowledge_irq
 * functions defined and the has_irq flag set.
 *
 * @param device Serial device to enable irqs on
 * @note This function should only be called from the AppleSerialShim kext
 */
kern_return_t
serial_irq_enable(serial_device_t device)
{
	struct pe_serial_functions *fns = get_serial_functions(device);

	if (!fns || !fns->has_irq || disable_uart_irq) {
		return KERN_FAILURE;
	}

	serial_irq_status &= ~device;

	return KERN_SUCCESS;
}

/**
 * Performs any actions needed to handle this IRQ. Wakes up the thread waiting
 * on the interrupt if one exists.
 *
 * @param device Serial device that generated the IRQ.
 * @note Interrupts will have already been cleared and disabled by serial_irq_filter.
 * @note This function should only be called from the AppleSerialShim kext.
 */
kern_return_t
serial_irq_action(serial_device_t device)
{
	struct pe_serial_functions *fns = get_serial_functions(device);

	if (!fns || !fns->has_irq) {
		return KERN_FAILURE;
	}

	/**
	 * Because IRQs are enabled only when we know a thread is about to sleep, we
	 * can call wake up and reasonably expect there to be a thread waiting.
	 */
	thread_wakeup(fns);

	return KERN_SUCCESS;
}

/**
 * Returns true if the pending IRQ for device is one that can be handled by the
 * platform serial driver.
 *
 * @param device Serial device that generated the IRQ.
 * @note This function is called from a primary interrupt context and should be
 *       kept lightweight.
 * @note This function should only be called from the AppleSerialShim kext
 */
bool
serial_irq_filter(serial_device_t device)
{
	struct pe_serial_functions *fns = get_serial_functions(device);

	if (!fns || !fns->has_irq) {
		return false;
	}

	/**
	 * Disable IRQs until next time a thread waits for an interrupt to prevent an interrupt storm.
	 */
	const bool had_irqs_enabled = fns->disable_irq();
	const bool was_our_interrupt = fns->acknowledge_irq();

	/* Re-enable IRQs if the interrupt wasn't for us. */
	if (had_irqs_enabled && !was_our_interrupt) {
		fns->enable_irq();
	}

	return was_our_interrupt;
}

/**
 * Prepares all serial devices to go to sleep by draining the hardware FIFOs
 * and disabling interrupts.
 */
void
serial_go_to_sleep(void)
{
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		if (irq_available_and_ready(fns)) {
			fns->disable_irq();
		}
		fns = fns->next;
	}

#ifdef APPLE_UART
	/* APPLE_UART needs to drain FIFO before sleeping */
	if (get_serial_functions(SERIAL_APPLE_UART)) {
		apple_uart_drain_fifo();
	}
#endif /* APPLE_UART */
}
