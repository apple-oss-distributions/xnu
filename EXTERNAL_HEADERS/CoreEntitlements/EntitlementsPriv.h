//
//  EntitlementsPriv.h
//  CoreEntitlements
//


#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "Entitlements.h"
#include "der_vm.h"

#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#error This is a private API, please consult with the Trusted Execution team before using this. Misusing these functions will lead to security issues.
#endif

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

#ifdef __cplusplus
}
#endif
