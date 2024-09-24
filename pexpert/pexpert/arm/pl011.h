/**
 * @file pl011.h
 *
 * @brief Contains all the types necessary to ergonomically interact with the
 * ARM PrimeCell UART (PL011).
 */

#include <stdint.h>

typedef union {
	uint32_t raw;
	struct {
		uint32_t data : 8;
		uint32_t fe : 1;
		uint32_t pe : 1;
		uint32_t be : 1;
		uint32_t oe : 1;
	};
} uartdr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t fe : 1;
		uint32_t pe : 1;
		uint32_t be : 1;
		uint32_t oe : 1;
	};
} uartrsr_uartecr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t cts : 1;
		uint32_t dsr : 1;
		uint32_t dcd : 1;
		uint32_t busy : 1;
		uint32_t rxfe : 1;
		uint32_t txff : 1;
		uint32_t rxff : 1;
		uint32_t txfe : 1;
		uint32_t ri : 1;
	};
} uartfr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t ilpdvsr : 8;
	};
} uartilpr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t baud_divint : 16;
	};
} uartibrd_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t baud_divfrac : 6;
	};
} uartfbrd_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t brk : 1;
		uint32_t pen : 1;
		uint32_t eps : 1;
		uint32_t stp2 : 1;
		uint32_t fen : 1;
		uint32_t wlen : 2;
		uint32_t sps : 1;
	};
} uartlcr_h_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t uarten : 1;
		uint32_t siren : 1;
		uint32_t sirlp : 1;
		uint32_t : 4;
		uint32_t lbe : 1;
		uint32_t txe : 1;
		uint32_t rxe : 1;
		uint32_t dtr : 1;
		uint32_t rts : 1;
		uint32_t out1 : 1;
		uint32_t out2 : 1;
		uint32_t rtsen : 1;
		uint32_t ctsen : 1;
	};
} uartcr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t txiflsel : 3;
		uint32_t rxiflsel : 3;
	};
} uartifls_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rimim : 1;
		uint32_t ctsmim : 1;
		uint32_t dcdmim : 1;
		uint32_t dsrmim : 1;
		uint32_t rxim : 1;
		uint32_t txim : 1;
		uint32_t rtim : 1;
		uint32_t feim : 1;
		uint32_t peim : 1;
		uint32_t beim : 1;
		uint32_t oeim : 1;
	};
} uartimsc_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rirmis : 1;
		uint32_t ctsrmis : 1;
		uint32_t dcdrmis : 1;
		uint32_t dsrrmis : 1;
		uint32_t rxris : 1;
		uint32_t txris : 1;
		uint32_t rtris : 1;
		uint32_t feris : 1;
		uint32_t peris : 1;
		uint32_t beris : 1;
		uint32_t oeris : 1;
	};
} uartris_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rimmis : 1;
		uint32_t ctsmmis : 1;
		uint32_t dcdmmis : 1;
		uint32_t dsrmmis : 1;
		uint32_t rxmis : 1;
		uint32_t txmis : 1;
		uint32_t rtmis : 1;
		uint32_t femis : 1;
		uint32_t pemis : 1;
		uint32_t bemis : 1;
		uint32_t oemis : 1;
	};
} uartmis_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rimic : 1;
		uint32_t ctsmic : 1;
		uint32_t dcdmic : 1;
		uint32_t dsrmic : 1;
		uint32_t rxic : 1;
		uint32_t txic : 1;
		uint32_t rtic : 1;
		uint32_t feic : 1;
		uint32_t peic : 1;
		uint32_t beic : 1;
		uint32_t oeic : 1;
	};
} uarticr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t rxdmae : 1;
		uint32_t txdmae : 1;
		uint32_t dmaonerr : 1;
	};
} uartdmacr_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t partnumber0 : 8;
	};
} uart_periph_id0_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t partnumber1 : 4;
		uint32_t designer0 : 4;
	};
} uart_periph_id1_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t designer1 : 4;
		uint32_t revision : 4;
	};
} uart_periph_id2_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t configuration : 8;
	};
} uart_periph_id3_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t uart_pcell_id0 : 8;
	};
} uart_pcell_id0_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t uart_pcell_id1 : 8;
	};
} uart_pcell_id1_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t uart_pcell_id2 : 8;
	};
} uart_pcell_id2_t;

typedef union {
	uint32_t raw;
	struct {
		uint32_t uart_pcell_id3 : 8;
	};
} uart_pcell_id3_t;

typedef struct {
	uartdr_t uartdr;
	uartrsr_uartecr_t uartrsr_uartecr;
	uint8_t _reserved0[0x10];
	uartfr_t uartfr;
	uint8_t _reserved1[0x4];
	uartilpr_t uartilpr;
	uartibrd_t uartibrd;
	uartfbrd_t uartfbrd;
	uartlcr_h_t uartlcr_h;
	uartcr_t uartcr;
	uartifls_t uartifls;
	uartimsc_t uartimsc;
	uartris_t uartris;
	uartmis_t uartmis;
	uarticr_t uarticr;
	uartdmacr_t uartdmacr;
	uint8_t _reserved2[0x34];
	uint8_t _reserved3[0x10];
	uint8_t _reserved4[0xf40];
	uint8_t _reserved5[0x10];
	uart_periph_id0_t uart_periph_id0;
	uart_periph_id1_t uart_periph_id1;
	uart_periph_id2_t uart_periph_id2;
	uart_periph_id3_t uart_periph_id3;
	uart_pcell_id0_t uart_pcell_id0;
	uart_pcell_id1_t uart_pcell_id1;
	uart_pcell_id2_t uart_pcell_id2;
	uart_pcell_id3_t uart_pcell_id3;
} pl011_registers_t;
