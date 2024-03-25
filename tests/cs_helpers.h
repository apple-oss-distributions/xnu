/*
 * Demotes the current task to a non-platform binary for testing purposes
 *
 * NOTE: platform-ness is tracked in many different places, and this API only
 * affects particular bits in the kernel - double check that it does what you want before using
 *
 * Returns: 0 on success, nonzero on failure
 */
extern int
remove_platform_binary(void);
