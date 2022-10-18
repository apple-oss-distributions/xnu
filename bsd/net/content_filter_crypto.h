/*
 * Copyright (c) 2019, 2022 Apple Inc.
 * All rights reserved.
 */

#ifndef __content_filter_crypto_h
#define __content_filter_crypto_h

#include <net/content_filter.h>

extern cfil_crypto_state_t
cfil_crypto_init_client(cfil_crypto_key client_key);

extern void
cfil_crypto_cleanup_state(cfil_crypto_state_t state);

extern int
cfil_crypto_sign_data(cfil_crypto_state_t state, cfil_crypto_data_t data,
    const struct iovec *extra_data, size_t extra_data_count,
    cfil_crypto_signature signature, u_int32_t *signature_length);

#endif // __content_filter_crypto_h
