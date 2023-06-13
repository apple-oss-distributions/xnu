//
//  EntitlementsPriv.h
//  CoreEntitlements
//


#ifndef CORE_ENTITLEMENTS_ENTS_PRIV_H
#define CORE_ENTITLEMENTS_ENTS_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <CoreEntitlements/Entitlements.h>
#include <CoreEntitlements/der_vm.h>

#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#error This is a private API, please consult with the Trusted Execution team before using this. Misusing these functions will lead to security issues.
#endif

__ptrcheck_abi_assume_single();

struct CEQueryContext {
    der_vm_context_t der_context;
    bool managed;
};


CEError_t CEAcquireUnmanagedContext(const CERuntime_t rt, CEValidationResult validationResult, struct CEQueryContext* ctx);

/*!
 * @function CEConjureContextFromDER
 * @brief Conjures up an object from thin air that you can query. Don't use it.
 * @note It does no validation.
 */
struct CEQueryContext CEConjureContextFromDER(der_vm_context_t der_context);

CEQueryOperation_t* CECreateStringOpInplace(CEQueryOperation_t* storage, CEQueryOpOpcode_t op, const char *__counted_by(len) data, size_t len);
CEQueryOperation_t* CECreateNumericOpInplace(CEQueryOperation_t* storage, CEQueryOpOpcode_t op, int64_t param);

#ifdef __cplusplus
}
#endif

#endif
