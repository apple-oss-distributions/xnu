/*!
 * @header
 * Encapsulation which describes an Image4 trust evaluation procedure. The type
 * of procedure impacts the result delivered to the
 * {@link image4_trust_evaluation_result_t}.
 *
 * All trust evaluations require a manifest to be present in the trust object.
 */
#ifndef __IMAGE4_API_TRUST_EVALUATION_H
#define __IMAGE4_API_TRUST_EVALUATION_H

#include <image4/image4.h>
#include <image4/types.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_TRUST_EVALUATION_EXEC
 * The trust evaluation is intended to execute firmware in the designated
 * environment. This is to be used for either first- or second-stage boots.
 *
 * This type of trust evaluation requires a payload.
 *
 * @section Trust Evaluation Result
 * Upon successful evaluation, the result is a pointer to the unwrapped Image4
 * payload bytes.
 *
 * @discussion
 * This trust evaluation is supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_exec;
#define IMAGE4_TRUST_EVALUATION_EXEC (&_image4_trust_evaluation_exec)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_exec);

/*!
 * @const IMAGE4_TRUST_EVALUATION_PREFLIGHT
 * The trust evaluation is intended to preflight a manifest to verify that it is
 * likely to be accepted during a boot trust evaluation in the future. This is
 * a best effort evaluation, and depending on the environment, certain
 * enforcement policies may be relaxed due to the relevant information not being
 * available.
 *
 * This type of trust evaluation does not require a payload.
 *
 * @section Trust Evaluation Result
 * The result is an error code indicating whether the manifest is likely to be
 * accepted by the environment.
 *
 * @discussion
 * This type of trust evaluation is not supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_preflight;
#define IMAGE4_TRUST_EVALUATION_PREFLIGHT (&_image4_trust_evaluation_preflight)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_preflight);

/*!
 * @const IMAGE4_TRUST_EVALUATION_SIGN
 * The trust evaluation is intended to facilitate counter-signing the manifest.
 *
 * @section Trust Evaluation Result
 * Upon successful evaluation, the result is a pointer to the digest of the
 * manifest. The digest is computed using the algorithm specified by the
 * environment.
 *
 * @discussion
 * This type of trust evaluation is not supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_sign;
#define IMAGE4_TRUST_EVALUATION_SIGN (&_image4_trust_evaluation_sign)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_sign);

/*!
 * @const IMAGE4_TRUST_EVALUATION_BOOT
 * The trust evaluation is intended to bootstrap a subsequent trust evaluation
 * in a chain of trust. The ultimate purpose of the chain of trust must be to
 * either preflight a manifest or sign it.
 *
 * This type of trust evaluation does not require a payload.
 *
 * @section Trust Evaluation Result
 * This type of trust evaluation is not intended to be performed directly by way
 * of {@link image4_trust_evaluate}. It is instead intended to create a trust
 * object which can be used as a previous stage of boot for another trust object
 * by way of {@link image4_trust_set_booter}.
 *
 * However, if the caller wishes to perform a boot trust evaluation directly,
 * then the trust evaluation result equivalent to that of
 * {@link IMAGE4_TRUST_EVALUATION_SIGN}.
 *
 * @discussion
 * This trust evaluation is supported on all targets.
 */
IMAGE4_API_AVAILABLE_SPRING_2024
OS_EXPORT
const image4_trust_evaluation_t _image4_trust_evaluation_boot;
#define IMAGE4_TRUST_EVALUATION_BOOT (&_image4_trust_evaluation_boot)
IMAGE4_XNU_AVAILABLE_INDIRECT(_image4_trust_evaluation_boot);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_API_TRUST_EVALUATION_H
