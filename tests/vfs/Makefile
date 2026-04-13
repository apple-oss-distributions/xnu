INCLUDED_TEST_SOURCE_DIRS += vfs

# VFS Test Specific Configurations

# Add common libraries to all VFS tests using correct target format
VFS_TESTS := $(addprefix vfs/,$(patsubst %.c,%,$(notdir $(wildcard vfs/*.c))))
$(VFS_TESTS): OTHER_LDFLAGS += -lsandbox -ldarwintest_utils

# Tests with specific entitlements
vfs/longpaths: CODE_SIGN_ENTITLEMENTS = vfs/longpaths.entitlements
vfs/devfs_fdesc: CODE_SIGN_ENTITLEMENTS = vfs/devfs_fdesc.entitlements
vfs/openbyid_stress: CODE_SIGN_ENTITLEMENTS = vfs/openbyid_stress.entitlements
