/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdint.h>
#include <mach/exclaves.h>
#include <mach/kern_return.h>

#include "exclaves_boot.h"
#include "exclaves_debug.h"
#include "exclaves_resource.h"
#include "exclaves_sensor.h"

#if CONFIG_EXCLAVES

#include <kern/locks.h>
#include <kern/thread_call.h>

#include "kern/exclaves.tightbeam.h"

/* -------------------------------------------------------------------------- */
#pragma mark EIC

#define EXCLAVES_EIC "com.apple.service.ExclaveIndicatorController"

/* The minimum time a sensor is on. */
#define EXCLAVES_EIC_MIN_SENSOR_TIME (3100 * NSEC_PER_MSEC) /* 3.1 seconds */

/* Default to 30Hz */
static uint64_t exclaves_display_healthcheck_rate_hz = 30;

static exclaveindicatorcontroller_sensorrequest_s eic_client;

static inline __unused exclaveindicatorcontroller_sensortype_s
sensor_type_to_eic_sensortype(exclaves_sensor_type_t type)
{
	assert3u(type, >, 0);
	assert3u(type, <=, EXCLAVES_SENSOR_MAX);

	switch (type) {
	case EXCLAVES_SENSOR_CAM:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_CAM;
	case EXCLAVES_SENSOR_MIC:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_MIC;
	case EXCLAVES_SENSOR_CAM_ALT_FACEID:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_CAM_ALT_FACEID;
	case EXCLAVES_SENSOR_CAM_ALT_FACEID_DELAYED:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_CAM_ALT_FACEID_DELAYED;
	default:
		panic("unknown sensor type");
	}
}

static inline exclaves_sensor_status_t
eic_sensorstatus_to_sensor_status(exclaveindicatorcontroller_sensorstatusresponse_s status)
{
	assert3u(status, >, 0);
	assert3u(status, <=, EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_PENDING);

	switch (status) {
	case EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_ALLOWED:
		return EXCLAVES_SENSOR_STATUS_ALLOWED;
	case EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_DENIED:
		return EXCLAVES_SENSOR_STATUS_DENIED;
	case EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_CONTROL:
		return EXCLAVES_SENSOR_STATUS_CONTROL;
	case EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_PENDING:
		return EXCLAVES_SENSOR_STATUS_PENDING;
	default:
		panic("unknown sensor status");
	}
}

static kern_return_t
exclaves_eic_init(void)
{
	exclaves_id_t eic_id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL,
	    EXCLAVES_EIC);

	if (eic_id == EXCLAVES_INVALID_ID) {
		exclaves_requirement_assert(EXCLAVES_R_EIC,
		    "exclaves indicator controller not found");
		return KERN_SUCCESS;
	}

	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, eic_id, TB_ENDPOINT_OPTIONS_NONE);

	tb_error_t ret =
	    exclaveindicatorcontroller_sensorrequest__init(&eic_client, ep);

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
exclaves_eic_tick_rate(uint64_t rate_hz)
{
	exclaveindicatorcontroller_indicatorrefreshrate_s rate;

	/* Round up to nearest supported value. */
	switch (rate_hz) {
	case 0 ... 30:
		exclaves_display_healthcheck_rate_hz = 30;
		rate.tag = EXCLAVEINDICATORCONTROLLER_INDICATORREFRESHRATE__HZ_30;
		break;
	case 31 ... 60:
		exclaves_display_healthcheck_rate_hz = 60;
		rate.tag = EXCLAVEINDICATORCONTROLLER_INDICATORREFRESHRATE__HZ_60;
		break;
	default:
		exclaves_display_healthcheck_rate_hz = 120;
		rate.tag = EXCLAVEINDICATORCONTROLLER_INDICATORREFRESHRATE__HZ_120;
		break;
	}

	tb_error_t ret = exclaveindicatorcontroller_sensorrequest_setindicatorrefreshrate(
		&eic_client, &rate, ^(__unused exclaveindicatorcontroller_requesterror_s result) {});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
exclaves_eic_sensor_start(exclaves_sensor_type_t __unused sensor_type,
    __assert_only uint64_t flags, exclaves_sensor_status_t *status)
{
	assert3p(status, !=, NULL);
	assert3u(flags, ==, 0);

	*status = EXCLAVES_SENSOR_STATUS_ALLOWED;
	return KERN_SUCCESS;
}

static kern_return_t
exclaves_eic_sensor_stop(exclaves_sensor_type_t __unused sensor_type)
{
	return KERN_SUCCESS;
}

static kern_return_t
exclaves_eic_sensor_status(exclaves_sensor_type_t __unused sensor_type,
    __assert_only uint64_t flags, exclaves_sensor_status_t *status)
{
	assert3p(status, !=, NULL);
	assert3u(flags, ==, 0);

	*status = EXCLAVES_SENSOR_STATUS_ALLOWED;
	return KERN_SUCCESS;
}

/*
 * It is intentional to keep "buffer" untyped here as it avoids xnu having to
 * understand what those IDs are at all. They are simply passed through from the
 * resource table as-is.
 */
static kern_return_t
exclaves_eic_sensor_copy(uint32_t buffer, uint64_t size1, uint64_t offset1,
    uint64_t size2, uint64_t offset2, exclaves_sensor_status_t *status)
{
	assert3u(size1, >, 0);
	assert3p(status, !=, NULL);

	tb_error_t ret = exclaveindicatorcontroller_sensorrequest_copybuffer(
		&eic_client, buffer, offset1, size1, offset2, size2,
		^(exclaveindicatorcontroller_sensorstatusresponse_s result) {
		*status = eic_sensorstatus_to_sensor_status(result);
	});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static bool
exclaves_sensor_tick(void)
{
	__block bool again = true;
	__unused tb_error_t ret = exclaveindicatorcontroller_sensorrequest_tick(
		&eic_client, ^(bool result) {
		again = result;
	});
	assert3u(ret, ==, TB_ERROR_SUCCESS);

	return again;
}

/* -------------------------------------------------------------------------- */
#pragma mark sensor

static LCK_GRP_DECLARE(sensor_lck_grp, "exclaves_sensor");

typedef struct {
	/*
	 * Count of how many times sensor_start has been called on this sensor
	 * without a corresponding sensor_stop.
	 */
	uint64_t s_startcount;

	/* Last start time. */
	uint64_t s_start_abs;

	/* Last stop time. */
	uint64_t s_stop_abs;

	/* mutex to protect updates to the above */
	lck_mtx_t s_mutex;

	/* Keep track of whether this sensor was initialised or not. */
	bool s_initialised;
} exclaves_sensor_t;

/**
 * A reverse lookup table for the sensor resources,
 * as the kpi uses sensor ids directly to access the same resources */
static exclaves_sensor_t sensors[EXCLAVES_SENSOR_MAX];

/*
 * A thread call used to periodically call "status" on any open sensors.
 */
static thread_call_t sensor_healthcheck_tcall = NULL;

static inline bool
valid_sensor(exclaves_sensor_type_t sensor_type)
{
	switch (sensor_type) {
	case EXCLAVES_SENSOR_CAM:
	case EXCLAVES_SENSOR_MIC:
	case EXCLAVES_SENSOR_CAM_ALT_FACEID:
	case EXCLAVES_SENSOR_CAM_ALT_FACEID_DELAYED:
		return true;
	default:
		return false;
	}
}

static inline exclaves_sensor_t *
sensor_type_to_sensor(exclaves_sensor_type_t sensor_type)
{
	assert(valid_sensor(sensor_type));
	return &sensors[sensor_type - 1];
}

/* Calculate the next healthcheck time. */
static void
healthcheck_deadline(uint64_t *deadline, uint64_t *leeway)
{
	const uint32_t interval =
	    NSEC_PER_SEC / exclaves_display_healthcheck_rate_hz;
	clock_interval_to_deadline(interval, 1, deadline);
	nanoseconds_to_absolutetime(interval / 2, leeway);
}

/*
 * Called from the threadcall to call into exclaves with a status command for
 * every started sensor. Re-arms itself so it runs at a frequency set by the
 * display healthcheck rate. Exits when there are no longer any started sensors.
 * A sensor has a minimum on-time. For stopped sensors, call back into exclaves
 * until this minimum time has been reached.
 */
static void
exclaves_sensor_healthcheck(__unused void *param0, __unused void *param1)
{
	uint64_t hc_leeway, hc_deadline;

	/*
	 * Calculate the next deadline up-front so the overhead of calling into
	 * exclaves doesn't add to the period.
	 */
	healthcheck_deadline(&hc_deadline, &hc_leeway);

	if (exclaves_sensor_tick()) {
		thread_call_enter_delayed_with_leeway(sensor_healthcheck_tcall,
		    NULL, hc_deadline, hc_leeway, THREAD_CALL_DELAY_LEEWAY);
	}
}

static kern_return_t
exclaves_sensor_init(void)
{
	kern_return_t kr = exclaves_eic_init();
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	for (uint32_t i = 1; i <= EXCLAVES_SENSOR_MAX; i++) {
		exclaves_sensor_t *sensor = sensor_type_to_sensor(i);

		lck_mtx_init(&sensor->s_mutex, &sensor_lck_grp, NULL);

		sensor->s_startcount = 0;
		sensor->s_initialised = true;
	}

	sensor_healthcheck_tcall =
	    thread_call_allocate_with_priority(exclaves_sensor_healthcheck,
	    NULL, THREAD_CALL_PRIORITY_KERNEL);

	return KERN_SUCCESS;
}
EXCLAVES_BOOT_TASK(exclaves_sensor_init, EXCLAVES_BOOT_RANK_ANY);

kern_return_t
exclaves_sensor_start(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	if (!valid_sensor(sensor_type)) {
		return KERN_INVALID_ARGUMENT;
	}

	exclaves_sensor_t *sensor = sensor_type_to_sensor(sensor_type);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&sensor->s_mutex);
	kern_return_t kr;

	if (sensor->s_startcount == UINT64_MAX) {
		lck_mtx_unlock(&sensor->s_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	if (sensor->s_startcount > 0) {
		kr = exclaves_eic_sensor_status(sensor_type, flags, status);
		if (kr == KERN_SUCCESS) {
			sensor->s_startcount += 1;
		}
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	// call start iff startcount is 0
	kr = exclaves_eic_sensor_start(sensor_type, flags, status);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	sensor->s_start_abs = mach_absolute_time();
	sensor->s_startcount += 1;

	lck_mtx_unlock(&sensor->s_mutex);

	/* Kick off the periodic status check. */
	(void)thread_call_enter(sensor_healthcheck_tcall);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_sensor_stop(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	if (!valid_sensor(sensor_type)) {
		return KERN_INVALID_ARGUMENT;
	}

	exclaves_sensor_t *sensor = sensor_type_to_sensor(sensor_type);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	kern_return_t kr;

	lck_mtx_lock(&sensor->s_mutex);

	if (sensor->s_startcount == 0) {
		lck_mtx_unlock(&sensor->s_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	if (sensor->s_startcount > 1) {
		kr = exclaves_eic_sensor_status(sensor_type, flags, status);
		if (kr == KERN_SUCCESS) {
			sensor->s_startcount -= 1;
		}
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	// call stop iff startcount is going to go to 0
	kr = exclaves_eic_sensor_stop(sensor_type);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	sensor->s_stop_abs = mach_absolute_time();
	sensor->s_startcount = 0;

	kr = exclaves_eic_sensor_status(sensor_type, flags, status);

	lck_mtx_unlock(&sensor->s_mutex);

	return kr;
}

kern_return_t
exclaves_sensor_status(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	if (!valid_sensor(sensor_type)) {
		return KERN_INVALID_ARGUMENT;
	}

	exclaves_sensor_t *sensor = sensor_type_to_sensor(sensor_type);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	return exclaves_eic_sensor_status(sensor_type, flags, status);
}

kern_return_t
exclaves_sensor_tick_rate(uint64_t rate_hz)
{
	/*
	 * Make sure that the initialisation has taken place before calling into
	 * the EIC. Any sensor is sufficient.
	 */
	exclaves_sensor_t *sensor = sensor_type_to_sensor(EXCLAVES_SENSOR_CAM);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	return exclaves_eic_tick_rate(rate_hz);
}

kern_return_t
exclaves_display_healthcheck_rate(uint64_t __unused ns)
{
	/* Deprecated, no longer does anything */
	return KERN_SUCCESS;
}

kern_return_t
exclaves_sensor_copy(uint32_t buffer, uint64_t size1, uint64_t offset1,
    uint64_t size2, uint64_t offset2, exclaves_sensor_status_t *status)
{
	/*
	 * Make sure that the initialisation has taken place before calling into
	 * the EIC. Any sensor is sufficient.
	 */
	exclaves_sensor_t *sensor = sensor_type_to_sensor(EXCLAVES_SENSOR_CAM);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}


	return exclaves_eic_sensor_copy(buffer, size1, offset1, size2, offset2,
	           status);
}

kern_return_t
exclaves_indicator_min_on_time_deadlines(struct exclaves_indicator_deadlines *deadlines)
{
	assert(deadlines);

	//For now, only one version is supported. Return an error if libsyscall sends us any other versions
	if (deadlines->version != 1) {
		return KERN_INVALID_ARGUMENT;
	}

	// Make sure that the initialisation has taken place before calling into
	// the EIC. Any sensor is sufficient.
	exclaves_sensor_t *sensor = sensor_type_to_sensor(EXCLAVES_SENSOR_CAM);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	tb_error_t ret = exclaveindicatorcontroller_sensorrequest_getmotstate(
		&eic_client, ^(exclaveindicatorcontroller_motstate_s result) {
		deadlines->camera_indicator = result.deadlinecil;
		deadlines->mic_indicator = result.deadlinemil;
		deadlines->faceid_indicator = result.deadlinefid;
	});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}



#else /* CONFIG_EXCLAVES */

kern_return_t
exclaves_display_healthcheck_rate(__unused uint64_t ns)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_sensor_tick_rate(uint64_t __unused rate_hz)
{
	return KERN_NOT_SUPPORTED;
}

#endif /* CONFIG_EXCLAVES */
