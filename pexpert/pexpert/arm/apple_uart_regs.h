/*
 * Copyright (c) 2000-2022 Apple Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_APPLE_UART_REGS_H
#define _PEXPERT_ARM_APPLE_UART_REGS_H

#define APPLE_UART

typedef union {
	uint32_t raw;
	struct {
		uint32_t receive_mode : 2;
		uint32_t transmit_mode : 2;
		uint32_t send_break_signal : 1;
		uint32_t loop_back_mode : 1;
		uint32_t : 1;
		uint32_t rx_time_out_enable : 1;
		uint32_t : 1;
		uint32_t new_receive_time_out_interrupt_enable : 1;
		uint32_t clock_selection : 1;
		uint32_t receive_time_out_interrupt_enable : 1;
		uint32_t receive_interrupt_enable : 1;
		uint32_t transmit_interrupt : 1;
		uint32_t error_interrupt_enable : 1;
		uint32_t unspecified : 1;
		uint32_t auto_baud_rate_interrupt_enable : 1;
		uint32_t auto_baud_rate_counter_start_command : 1;
		uint32_t mask_dma_request_enable : 1;
		uint32_t transmit_stop : 1;
		uint32_t sw_rst : 1;
		uint32_t dma_burst_en : 1;
		uint32_t : 10;
	};
} ucon_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t word_length : 2;
		uint32_t number_of_stop_bits : 1;
		uint32_t parity_mode : 3;
		uint32_t infra_red_mode : 1;
		uint32_t tolerant_mode : 1;
		uint32_t i_o_inverted_mode : 1;
		uint32_t : 23;
	};
} ulcon_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t fifo_enable : 1;
		uint32_t rx_fifo_reset : 1;
		uint32_t tx_fifo_reset : 1;
		uint32_t : 1;
		uint32_t rx_fifo_interrupt_trigger_level_dma_watermark : 2;
		uint32_t tx_fifo_interrupt_trigger_level_dma_watermark : 2;
		uint32_t nrts_trigger_level : 2;
		uint32_t : 22;
	};
} ufcon_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rx_fifo_count : 4;
		uint32_t tx_fifo_count : 4;
		uint32_t rx_fifo_full : 1;
		uint32_t tx_fifo_full : 1;
		uint32_t : 22;
	};
} ufstat_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t receive_buffer_data_ready : 1;
		uint32_t transmit_buffer_empty : 1;
		uint32_t transmitter_empty : 1;
		uint32_t receive_time_out_interrupt_status : 1;
		uint32_t receive_interrupt_status : 1;
		uint32_t transmit_interrupt_status : 1;
		uint32_t error_interrupt_status : 1;
		uint32_t : 1;
		uint32_t auto_baud_interrupt_status : 1;
		uint32_t new_receive_time_out_interrupt_status : 1;
		uint32_t : 22;
	};
} utrstat_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t ubr_div : 16;
		uint32_t sample_rate : 4;
		uint32_t : 12;
	};
} ubrdiv_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t txdata : 8;
		uint32_t : 24;
	};
} utxh_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rxdata : 8;
		uint32_t : 24;
	};
} urxh_t;

typedef struct {
	ulcon_t ulcon;
	ucon_t ucon;
	ufcon_t ufcon;
	uint32_t umcon;
	utrstat_t utrstat;
	uint32_t uerstat;
	ufstat_t ufstat;
	uint32_t umstat;
	utxh_t utxh;
	urxh_t urxh;
	ubrdiv_t ubrdiv;
	uint32_t uabrcnt;
	uint8_t rsvd0[4];
	uint32_t utxoffset;
	uint32_t urxoffset;
	uint32_t uver;
} apple_uart_registers_t;

typedef enum {
	UCON_CLOCK_SELECTION_PLCK = 0,
	UCON_CLOCK_SELECTION_NCLK = 1,
} ucon_clock_selection_t;

typedef enum {
	UCON_TRANSMIT_MODE_DISABLE = 0,
	UCON_TRANSMIT_MODE_INTERRUPT_OR_POLLING = 1,
	UCON_TRANSMIT_MODE_UNDEFINED = 2,
	UCON_TRANSMIT_MODE_DMA = 3,
} ucon_transmit_mode_t;

typedef enum {
	UCON_RECEIVE_MODE_DISABLE = 0,
	UCON_RECEIVE_MODE_INTERRUPT_OR_POLLING = 1,
	UCON_RECEIVE_MODE_UNDEFINED = 2,
	UCON_RECEIVE_MODE_DMA = 3,
} ucon_receive_mode_t;

typedef enum {
	ULCON_WORD_LENGTH_5_BITS = 0,
	ULCON_WORD_LENGTH_6_BITS = 1,
	ULCON_WORD_LENGTH_7_BITS = 2,
	ULCON_WORD_LENGTH_8_BITS = 3,
} ulcon_word_length_t;

typedef enum {
	ULCON_PARITY_MODE_NONE = 0,
	ULCON_PARITY_MODE_ODD = 4,
	ULCON_PARITY_MODE_EVEN = 5,
	ULCON_PARITY_MODE_1 = 6,
	ULCON_PARITY_MODE_0 = 7,
} ulcon_parity_mode_t;

typedef enum {
	ULCON_STOP_BITS_1 = 0,
	ULCON_STOP_BITS_2 = 1,
} ulcon_stop_bits_t;

typedef enum {
	UFCON_TX_FIFO_ITL_0_BYTES = 0,
	UFCON_TX_FIFO_ITL_4_BYTES = 1,
	UFCON_TX_FIFO_ITL_8_BYTES = 2,
	UFCON_TX_FIFO_ITL_12_BYTES = 3,
} ufcon_tx_fifo_itl_t;

#endif /* #define _PEXPERT_ARM_APPLE_UART_REGS_H */
