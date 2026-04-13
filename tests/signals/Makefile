INCLUDED_TEST_SOURCE_DIRS += signals

signals/signal_exit_reason: CODE_SIGN_ENTITLEMENTS = signals/signal_exit_reason.entitlements

signals/sendsig_stack_overflow: excserver
signals/sendsig_stack_overflow: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
signals/sendsig_stack_overflow: OTHER_LDFLAGS += -ldarwintest_utils -lpthread
signals/sendsig_stack_overflow: CODE_SIGN_ENTITLEMENTS = entitlements/set_exception_port.entitlement
