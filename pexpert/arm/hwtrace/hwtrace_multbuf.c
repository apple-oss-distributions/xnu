/*
 * Copyright (c) 2007-2023 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */

/* Required to know if we must compile the file. */
#include <pexpert/arm64/board_config.h>

/* If not DEBUG || DEV or trace to multbuf not supported,
 * do not compile the file. */
#if DEVELOPMENT || DEBUG
#endif /* DEVELOPMENT || DEBUG */
