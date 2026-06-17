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
#include <libkern/coreanalytics/coreanalytics.h>

#include "exclaves_boot.h"
#include "exclaves_debug.h"
#include "exclaves_resource.h"
#include "exclaves_sensor.h"

#if CONFIG_EXCLAVES

#include <kern/locks.h>
#include <kern/thread.h>

#include "kern/exclaves.tightbeam.h"

/* -------------------------------------------------------------------------- */
#pragma mark EIC

#define EXCLAVES_EIC "com.apple.service.ExclaveIndicatorController"
#define EXCLAVES_EIC_COPYREQUEST "com.apple.service.ExclaveIndicatorController.SensorCopyRequest"

/* The minimum time a sensor is on. */
#define EXCLAVES_EIC_MIN_SENSOR_TIME (3100 * NSEC_PER_MSEC) /* 3.1 seconds */

/* Default to 30Hz */
static uint64_t exclaves_display_healthcheck_rate_hz = 30;

static exclaveindicatorcontroller_sensorrequest_s eic_client;
static exclaveindicatorcontroller_sensorcopyrequest_s eic_copy_client;

CA_EVENT(exclave_indicator_controller_metrics_v1,
    CA_INT, metrics_duration_ms,
    CA_INT, num_sessions_mic,
    CA_INT, num_sessions_dropped_mic,
    CA_INT, num_sessions_denied_healthcheck_mic,
    CA_INT, num_sessions_denied_sensor_control_mic,
    CA_INT, duration_allowed_ms_mic,
    CA_INT, duration_pending_ms_mic,
    CA_INT, duration_control_ms_mic,
    CA_INT, duration_denied_ms_mic,
    CA_INT, bips_allowed_mic,
    CA_INT, bips_pending_mic,
    CA_INT, bips_control_mic,
    CA_INT, bips_denied_mic,

    CA_INT, num_sessions_cam,
    CA_INT, num_sessions_dropped_cam,
    CA_INT, num_sessions_denied_healthcheck_cam,
    CA_INT, num_sessions_denied_sensor_control_cam,
    CA_INT, duration_allowed_ms_cam,
    CA_INT, duration_pending_ms_cam,
    CA_INT, duration_control_ms_cam,
    CA_INT, duration_denied_ms_cam,
    CA_INT, bips_allowed_cam,
    CA_INT, bips_pending_cam,
    CA_INT, bips_control_cam,
    CA_INT, bips_denied_cam);

CA_EVENT(exclave_indicator_controller_chillpill_metrics_v1,
    CA_INT, chillpill_limit_ms,
    CA_INT, max_chillpill_used_ms,
    CA_INT, chillpill_bucket_0_100_ms,
    CA_INT, chillpill_bucket_101_200_ms,
    CA_INT, chillpill_bucket_201_300_ms,
    CA_INT, chillpill_bucket_301_400_ms,
    CA_INT, chillpill_bucket_401_500_ms,
    CA_INT, chillpill_bucket_501_600_ms,
    CA_INT, chillpill_bucket_601_700_ms,
    CA_INT, chillpill_bucket_701_800_ms,
    CA_INT, chillpill_bucket_801_900_ms,
    CA_INT, chillpill_bucket_901_1000_ms,
    CA_INT, chillpill_bucket_1001_1500_ms,
    CA_INT, chillpill_bucket_1501_2000_ms,
    CA_INT, chillpill_bucket_2001_2500_ms,
    CA_INT, chillpill_bucket_2501_3000_ms,
    CA_INT, chillpill_bucket_3000_plus_ms);

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
	case EXCLAVES_SENSOR_TEST:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_TEST;
	case EXCLAVES_SENSOR_TEST_MIL:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_TEST_MIL;
	case EXCLAVES_SENSOR_TEST_CIL:
		return EXCLAVEINDICATORCONTROLLER_SENSORTYPE_SENSOR_TEST_CIL;
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
#if defined(EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_EXPIRED)
	case EXCLAVEINDICATORCONTROLLER_SENSORSTATUSRESPONSE_SENSOR_EXPIRED:
		return EXCLAVES_SENSOR_STATUS_EXPIRED;
#endif
	default:
		panic("unknown sensor status");
	}
}


static kern_return_t
exclaves_eic_client_init(void)
{
	exclaves_id_t sensorrequest_id, sensorcopyrequest_id;
	tb_endpoint_t sensorrequest_endpoint, sensorcopyrequest_endpoint;
	tb_error_t ret = TB_ERROR_SUCCESS;

	sensorrequest_id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, EXCLAVES_EIC);
	if (sensorrequest_id == EXCLAVES_INVALID_ID) {
		exclaves_requirement_assert(EXCLAVES_R_EIC,
		    "exclaves indicator controller not found");
		return KERN_SUCCESS;
	}

	sensorcopyrequest_id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, EXCLAVES_EIC_COPYREQUEST);
	if (sensorcopyrequest_id == EXCLAVES_INVALID_ID) {
		exclaves_requirement_assert(EXCLAVES_R_EIC,
		    "ExclaveIndicatorController SensorCopyRequest service not found");
		return KERN_SUCCESS;
	}

	sensorrequest_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, sensorrequest_id, TB_ENDPOINT_OPTIONS_NONE);
	sensorcopyrequest_endpoint = tb_endpoint_create_with_value(TB_TRANSPORT_TYPE_XNU, sensorcopyrequest_id, TB_ENDPOINT_OPTIONS_NONE);

	ret = exclaveindicatorcontroller_sensorrequest__init(&eic_client, sensorrequest_endpoint);
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_requirement_assert(EXCLAVES_R_EIC, "failed to initialize eic sensor request client");
		return KERN_FAILURE;
	}

	ret = exclaveindicatorcontroller_sensorcopyrequest__init(&eic_copy_client, sensorcopyrequest_endpoint);
	if (ret != TB_ERROR_SUCCESS) {
		exclaves_requirement_assert(EXCLAVES_R_EIC, "failed to initialize eic sensor copy request client");
		/* Clean up first client (sensorrequest) if second client (sensorcopyrequest) init fails */
		exclaveindicatorcontroller_sensorrequest__destruct(&eic_client);
		return KERN_FAILURE;
	}


	return KERN_SUCCESS;
}

static kern_return_t
exclaves_eic_tick_rate(uint64_t rate_hz)
{
	tb_error_t ret = TB_ERROR_SUCCESS;
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

	/* BEGIN IGNORE CODESTYLE */
	ret = exclaveindicatorcontroller_sensorrequest_setindicatorrefreshrate(
	    &eic_client, &rate,
	    ^(__unused exclaveindicatorcontroller_requesterror_s result) {});
	/* END IGNORE CODESTYLE */

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

static kern_return_t
exclaves_eic_sensor_start(exclaves_sensor_type_t sensor_type,
    __assert_only uint64_t flags, exclaves_sensor_status_t *status)
{
	assert3p(status, !=, NULL);
	assert3u(flags, ==, 0);

	tb_error_t ret = TB_ERROR_SUCCESS;
	const exclaveindicatorcontroller_sensortype_s sensor =
	    sensor_type_to_eic_sensortype(sensor_type);

	ret = exclaveindicatorcontroller_sensorrequest_start(&eic_client, sensor,
	    ^(exclaveindicatorcontroller_sensorstatusresponse_s result) {
		*status = eic_sensorstatus_to_sensor_status(result);
	});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
exclaves_eic_sensor_stop(exclaves_sensor_type_t sensor_type)
{
	tb_error_t ret = TB_ERROR_SUCCESS;
	const exclaveindicatorcontroller_sensortype_s sensor =
	    sensor_type_to_eic_sensortype(sensor_type);

	ret = exclaveindicatorcontroller_sensorrequest_stop(&eic_client, sensor);

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
exclaves_eic_sensor_status(exclaves_sensor_type_t sensor_type,
    __assert_only uint64_t flags, exclaves_sensor_status_t *status)
{
	assert3p(status, !=, NULL);
	assert3u(flags, ==, 0);

	tb_error_t ret = TB_ERROR_SUCCESS;
	const exclaveindicatorcontroller_sensortype_s sensor =
	    sensor_type_to_eic_sensortype(sensor_type);

	ret = exclaveindicatorcontroller_sensorrequest_status(&eic_client, sensor,
	    ^(exclaveindicatorcontroller_sensorstatusresponse_s result) {
		*status = eic_sensorstatus_to_sensor_status(result);
	});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

/*
 * It is intentional to keep "buffer" untyped here as it avoids xnu having to
 * understand what those IDs are at all. They are simply passed through from the
 * resource table as-is.
 */
static kern_return_t
exclaves_eic_sensor_copy(uint64_t buffer, uint64_t size1, uint64_t offset1,
    uint64_t size2, uint64_t offset2, exclaves_sensor_status_t *status,
    bool *second_range)
{
	tb_error_t ret = TB_ERROR_SUCCESS;
	assert3u(size1, >, 0);
	assert3p(status, !=, NULL);
	assert3p(second_range, !=, NULL);

	*second_range = true;
	/* BEGIN IGNORE CODESTYLE */
	ret = exclaveindicatorcontroller_sensorcopyrequest_copy(
	    &eic_copy_client, buffer, offset1, size1, offset2, size2,
	    ^(exclaveindicatorcontroller_sensorstatusresponse_s result) {
		*status = eic_sensorstatus_to_sensor_status(result);
	});
	/* END IGNORE CODESTYLE */

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}


/* -------------------------------------------------------------------------- */
#pragma mark sensor resource

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

	/* Device id generated by EIC */
	exclaveindicatorcontroller_deviceid_s s_device_id;

	/* Keep track of whether this sensor was initialised or not. */
	bool s_initialised;
} exclaves_sensor_t;

/**
 * A reverse lookup table for the sensor resources,
 * as the kpi uses sensor ids directly to access the same resources */
static exclaves_sensor_t sensors[EXCLAVES_SENSOR_MAX];


static inline exclaves_sensor_type_t
sensor_id_to_sensor_type(uint64_t sensor_id)
{
	return (exclaves_sensor_type_t)(sensor_id);
}

static inline exclaves_device_type_t
sensor_id_to_device_type(uint64_t sensor_id)
{
	return (exclaves_device_type_t)SENSOR_ID_GET_DEVICE(sensor_id);
}


static inline bool
valid_sensor_id(uint64_t sensor_id)
{

	switch (sensor_id_to_sensor_type(sensor_id)) {
	case EXCLAVES_SENSOR_CAM:
	case EXCLAVES_SENSOR_MIC:
	case EXCLAVES_SENSOR_CAM_ALT_FACEID:
	case EXCLAVES_SENSOR_CAM_ALT_FACEID_DELAYED:
	case EXCLAVES_SENSOR_TEST:
	case EXCLAVES_SENSOR_TEST_MIL:
	case EXCLAVES_SENSOR_TEST_CIL:
		return true;
	default:
		return false;
	}
}

static inline exclaves_sensor_t *
sensor_type_to_sensor(exclaves_sensor_type_t sensor_type)
{
	assert3u(sensor_type, <=, EXCLAVES_SENSOR_MAX);
	return &sensors[sensor_type - 1];
}

static inline exclaves_sensor_t *
sensor_id_to_sensor(uint64_t sensor_id)
{
	return sensor_type_to_sensor(sensor_id_to_sensor_type(sensor_id));
}


static inline exclaves_device_type_t
arbitrated_buffer_id_to_device_type(uint64_t resource_id)
{
	return (exclaves_device_type_t)
	       ARBITRATED_BUFFER_MEMORY_ID_GET_DEVICE(resource_id);
}


static inline uint64_t
arbitrated_buffer_id_to_buffer(uint64_t resource_id)
{
	return ARBITRATED_BUFFER_MEMORY_ID_GET_BUFFER(resource_id);
}

static inline uint64_t
arbitrated_buffer_id_to_endpoint(uint64_t resource_id)
{
	return ARBITRATED_BUFFER_MEMORY_ID_GET_ENDPOINT(resource_id);
}


/* -------------------------------------------------------------------------- */
#pragma mark sensor operations

static thread_t sensor_tick_loop_thread = NULL;
static event_t sensor_tick_loop_event = (event_t) &sensor_tick_loop_event;
static LCK_MTX_DECLARE(sensor_tick_loop_mtx, &sensor_lck_grp);

__attribute__((noreturn))
static void
exclaves_sensor_tick_loop(__unused void *arg, __unused wait_result_t wr);

static kern_return_t
exclaves_sensor_boot(void)
{
	kern_return_t kr = exclaves_eic_client_init();
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	for (uint32_t i = 1; i <= EXCLAVES_SENSOR_MAX; i++) {
		exclaves_sensor_t *sensor = sensor_type_to_sensor(i);

		lck_mtx_init(&sensor->s_mutex, &sensor_lck_grp, NULL);

		sensor->s_startcount = 0;
		sensor->s_initialised = true;
	}


	kernel_thread_start(exclaves_sensor_tick_loop, NULL, &sensor_tick_loop_thread);
	thread_set_thread_name(sensor_tick_loop_thread, "exclaves_sensor_tick_loop");

	return KERN_SUCCESS;
}
EXCLAVES_BOOT_TASK(exclaves_sensor_boot, EXCLAVES_BOOT_RANK_ANY);

static kern_return_t
exclaves_sensor_init(exclaves_sensor_t *sensor,
    __unused exclaves_device_type_t device_type)
{
	kern_return_t kr = KERN_SUCCESS;
	lck_mtx_lock(&sensor->s_mutex);

	if (sensor->s_initialised) {
		lck_mtx_unlock(&sensor->s_mutex);
		return KERN_SUCCESS;
	}

	if (kr == KERN_SUCCESS) {
		sensor->s_initialised = true;
	}

	lck_mtx_unlock(&sensor->s_mutex);

	return kr;
}

kern_return_t
exclaves_sensor_id_init(uint64_t sensor_id)
{
	exclaves_sensor_t *sensor = NULL;
	exclaves_device_type_t device_type = sensor_id_to_device_type(sensor_id);


	if (!sensor || sensor->s_initialised) {
		return KERN_SUCCESS;
	}

	return exclaves_sensor_init(sensor, device_type);
}

kern_return_t
exclaves_sensor_id_start(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	kern_return_t kr;
	exclaves_sensor_t *sensor = NULL;
	exclaves_sensor_type_t sensor_type;

	{
		if (!valid_sensor_id(sensor_id)) {
			return KERN_INVALID_ARGUMENT;
		}
		sensor_type = sensor_id_to_sensor_type(sensor_id);
		sensor = sensor_id_to_sensor(sensor_id);
	}

	assert3p(sensor, !=, NULL);

	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&sensor->s_mutex);

	if (sensor->s_startcount == UINT64_MAX) {
		lck_mtx_unlock(&sensor->s_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	if (sensor->s_startcount > 0) {
		{
			kr = exclaves_eic_sensor_status(sensor_type, flags, status);
		}
		if (kr == KERN_SUCCESS) {
			sensor->s_startcount += 1;
		}
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	// call start iff startcount is 0
	{
		kr = exclaves_eic_sensor_start(sensor_type, flags, status);
	}
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	sensor->s_start_abs = mach_absolute_time();
	sensor->s_startcount += 1;

	lck_mtx_unlock(&sensor->s_mutex);

	/* Kick off the periodic status check. */
	/* the lock will be available only when the tick_loop thread is sleeping */
	lck_mtx_lock(&sensor_tick_loop_mtx);
	thread_wakeup(sensor_tick_loop_event);
	/* let the tick_loop thread retake the lock */
	lck_mtx_unlock(&sensor_tick_loop_mtx);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_sensor_id_stop(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	kern_return_t kr;
	exclaves_sensor_t *sensor = NULL;
	exclaves_sensor_type_t sensor_type;

	{
		if (!valid_sensor_id(sensor_id)) {
			return KERN_INVALID_ARGUMENT;
		}
		sensor_type = sensor_id_to_sensor_type(sensor_id);
		sensor = sensor_id_to_sensor(sensor_id);
	}

	assert3p(sensor, !=, NULL);

	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&sensor->s_mutex);

	if (sensor->s_startcount == 0) {
		lck_mtx_unlock(&sensor->s_mutex);
		return KERN_INVALID_ARGUMENT;
	}

	if (sensor->s_startcount > 1) {
		{
			kr = exclaves_eic_sensor_status(sensor_type, flags, status);
		}
		if (kr == KERN_SUCCESS) {
			sensor->s_startcount -= 1;
		}
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	// call stop iff startcount is going to go to 0
	{
		kr = exclaves_eic_sensor_stop(sensor_type);
	}
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&sensor->s_mutex);
		return kr;
	}

	sensor->s_stop_abs = mach_absolute_time();
	sensor->s_startcount = 0;

	{
		kr = exclaves_eic_sensor_status(sensor_type, flags, status);
	}

	lck_mtx_unlock(&sensor->s_mutex);

	return kr;
}

kern_return_t
exclaves_sensor_id_status(uint64_t sensor_id, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	kern_return_t kr;
	exclaves_sensor_t *sensor = NULL;
	exclaves_sensor_type_t sensor_type;

	{
		if (!valid_sensor_id(sensor_id)) {
			return KERN_INVALID_ARGUMENT;
		}
		sensor_type = sensor_id_to_sensor_type(sensor_id);
		sensor = sensor_id_to_sensor(sensor_id);
	}

	assert3p(sensor, !=, NULL);

	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	{
		kr = exclaves_eic_sensor_status(sensor_type, flags, status);
	}

	return kr;
}

kern_return_t
exclaves_sensor_buffer_id_copy(uint64_t resource_id, uint64_t size,
    uint64_t offset, uint64_t param1, uint64_t param2,
    exclaves_sensor_status_t *status, bool *second_range)
{
	kern_return_t kr;
	exclaves_sensor_t *sensor = NULL;
	exclaves_sensor_type_t sensor_type;
	exclaves_device_type_t device_type;
	uint64_t buffer = 0;

	device_type = arbitrated_buffer_id_to_device_type(resource_id);
	buffer = arbitrated_buffer_id_to_buffer(resource_id);

	{
		/*
		 * Make sure that the initialisation has taken place before calling into
		 * the EIC. Any sensor is sufficient.
		 */
		sensor_type = EXCLAVES_SENSOR_CAM;
		sensor = sensor_type_to_sensor(sensor_type);
	}

	assert3p(sensor, !=, NULL);

	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	{
		kr = exclaves_eic_sensor_copy(buffer, size, offset, param1, param2,
		    status, second_range);
	}

	return kr;
}
uint64_t
exclaves_sensor_buffer_id_endpoint(uint64_t resource_id)
{
	return arbitrated_buffer_id_to_endpoint(resource_id);
}

/* Exported KPI compatibility entry points */

kern_return_t
exclaves_sensor_start(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	return exclaves_sensor_id_start((uint64_t)sensor_type, flags, status);
}

kern_return_t
exclaves_sensor_stop(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	return exclaves_sensor_id_stop((uint64_t)sensor_type, flags, status);
}

kern_return_t
exclaves_sensor_status(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
	return exclaves_sensor_id_status((uint64_t)sensor_type, flags, status);
}

/* -------------------------------------------------------------------------- */
#pragma mark sensor timer

static uint64_t
exclaves_sensor_tick_calculate_deadline(void)
{
	uint64_t deadline;
	const uint32_t interval =
	    NSEC_PER_SEC / exclaves_display_healthcheck_rate_hz;
	clock_interval_to_deadline(interval, 1, &deadline);
	return deadline;
}

__attribute__((noinline))
static void
exclaves_sensor_tick_wait_indefinitely(void)
{
	lck_mtx_sleep(&sensor_tick_loop_mtx,
	    LCK_SLEEP_DEFAULT,
	    sensor_tick_loop_event,
	    THREAD_UNINT);
}

__attribute__((noinline))
static void
exclaves_sensor_tick_wait_with_deadline(uint64_t deadline)
{
	lck_mtx_sleep_deadline(&sensor_tick_loop_mtx,
	    LCK_SLEEP_DEFAULT,
	    sensor_tick_loop_event,
	    THREAD_UNINT,
	    deadline);
}

__attribute__((noreturn))
static void
exclaves_sensor_tick_loop(__unused void *arg, __unused wait_result_t wr)
{
	uint64_t deadline;
	bool next_tick_has_deadline = false;

	/* we always hold the lock below here, except while waiting */
	lck_mtx_lock(&sensor_tick_loop_mtx);

	for (;;) {
		if (next_tick_has_deadline) {
			exclaves_sensor_tick_wait_with_deadline(deadline);
		} else {
			/* wait for rearm by exclaves_sensor_id_start */
			exclaves_sensor_tick_wait_indefinitely();
		}
		deadline = exclaves_sensor_tick_calculate_deadline();
		next_tick_has_deadline = exclaves_sensor_tick();
	}

	__builtin_unreachable();
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

static kern_return_t
exclaves_sensor_get_and_clear_metrics(ca_event_t sensor_metrics_event,
    ca_event_t chillpill_event)
{
	if (!sensor_metrics_event || !chillpill_event) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Make sure that the initialisation has taken place before calling into
	 * the EIC. Any sensor is sufficient.
	 */
	exclaves_sensor_t *sensor = sensor_type_to_sensor(EXCLAVES_SENSOR_CAM);
	if (!sensor->s_initialised) {
		return KERN_FAILURE;
	}

	CA_EVENT_TYPE(exclave_indicator_controller_metrics_v1) * e =
	    sensor_metrics_event->data;
	CA_EVENT_TYPE(exclave_indicator_controller_chillpill_metrics_v1) * cp =
	    chillpill_event->data;

	tb_error_t ret = exclaveindicatorcontroller_sensorrequest_getandclearmetrics(
		&eic_client, ^(exclaveindicatorcontroller_sensorrequestmetrics_s result) {
		e->metrics_duration_ms = result.metricsdurationms;

		/* Microphone metrics */
		e->num_sessions_mic = result.numsessionsmic;
		e->num_sessions_dropped_mic = result.numsessionsdroppedmic;
		e->num_sessions_denied_healthcheck_mic = result.numsessionsdeniedhealthcheckmic;
		e->num_sessions_denied_sensor_control_mic = result.numsessionsdeniedsensorcontrolmic;
		e->duration_allowed_ms_mic = result.durationallowedmsmic;
		e->duration_pending_ms_mic = result.durationpendingmsmic;
		e->duration_control_ms_mic = result.durationcontrolmsmic;
		e->duration_denied_ms_mic = result.durationdeniedmsmic;
		e->bips_allowed_mic = result.bipsallowedmic;
		e->bips_pending_mic = result.bipspendingmic;
		e->bips_control_mic = result.bipscontrolmic;
		e->bips_denied_mic = result.bipsdeniedmic;

		/* Camera metrics */
		e->num_sessions_cam = result.numsessionscam;
		e->num_sessions_dropped_cam = result.numsessionsdroppedcam;
		e->num_sessions_denied_healthcheck_cam = result.numsessionsdeniedhealthcheckcam;
		e->num_sessions_denied_sensor_control_cam = result.numsessionsdeniedsensorcontrolcam;
		e->duration_allowed_ms_cam = result.durationallowedmscam;
		e->duration_pending_ms_cam = result.durationpendingmscam;
		e->duration_control_ms_cam = result.durationcontrolmscam;
		e->duration_denied_ms_cam = result.durationdeniedmscam;
		e->bips_allowed_cam = result.bipsallowedcam;
		e->bips_pending_cam = result.bipspendingcam;
		e->bips_control_cam = result.bipscontrolcam;
		e->bips_denied_cam = result.bipsdeniedcam;

		/* Chill pill metrics */
		cp->chillpill_limit_ms = result.chillpilllimitms;
		cp->max_chillpill_used_ms = result.maxchillpillusedms;
		cp->chillpill_bucket_0_100_ms = result.chillpillbucket0to100ms;
		cp->chillpill_bucket_101_200_ms = result.chillpillbucket101to200ms;
		cp->chillpill_bucket_201_300_ms = result.chillpillbucket201to300ms;
		cp->chillpill_bucket_301_400_ms = result.chillpillbucket301to400ms;
		cp->chillpill_bucket_401_500_ms = result.chillpillbucket401to500ms;
		cp->chillpill_bucket_501_600_ms = result.chillpillbucket501to600ms;
		cp->chillpill_bucket_601_700_ms = result.chillpillbucket601to700ms;
		cp->chillpill_bucket_701_800_ms = result.chillpillbucket701to800ms;
		cp->chillpill_bucket_801_900_ms = result.chillpillbucket801to900ms;
		cp->chillpill_bucket_901_1000_ms = result.chillpillbucket901to1000ms;
		cp->chillpill_bucket_1001_1500_ms = result.chillpillbucket1001to1500ms;
		cp->chillpill_bucket_1501_2000_ms = result.chillpillbucket1501to2000ms;
		cp->chillpill_bucket_2001_2500_ms = result.chillpillbucket2001to2500ms;
		cp->chillpill_bucket_2501_3000_ms = result.chillpillbucket2501to3000ms;
		cp->chillpill_bucket_3000_plus_ms = result.chillpillbucket3000plusms;
	});

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

void
exclaves_indicator_metrics_report(void)
{
	ca_event_t sensor_metrics_event =
	    CA_EVENT_ALLOCATE(exclave_indicator_controller_metrics_v1);
	ca_event_t chillpill_event =
	    CA_EVENT_ALLOCATE(exclave_indicator_controller_chillpill_metrics_v1);
	kern_return_t kr = exclaves_sensor_get_and_clear_metrics(
		sensor_metrics_event, chillpill_event);

	if (kr != KERN_SUCCESS) {
		CA_EVENT_DEALLOCATE(sensor_metrics_event);
		CA_EVENT_DEALLOCATE(chillpill_event);
		return;
	}

	CA_EVENT_SEND(sensor_metrics_event);
	CA_EVENT_SEND(chillpill_event);
}

#else /* CONFIG_EXCLAVES */

/* -------------------------------------------------------------------------- */
#pragma mark KPI stubs

kern_return_t
exclaves_sensor_start(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_sensor_stop(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_sensor_status(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

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
