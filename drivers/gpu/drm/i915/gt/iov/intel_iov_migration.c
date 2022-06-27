// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov_migration.h"
#include "intel_iov_query.h"
#include "intel_iov_utils.h"
#include "intel_iov.h"

/**
 * intel_iov_migration_reinit_guc - Re-initialize GuC communication.
 * @iov: the iov struct
 *
 * After migration, we need to reestablish communication with GuC and
 * re-query all VF configuration to make sure they match previous
 * provisioning. Note that most of VF provisioning shall be the same,
 * except GGTT range, since GGTT is not virtualized per-VF.
 *
 * Returns: 0 if the operation completed successfully, or a negative error
 * code otherwise.
 */
int intel_iov_migration_reinit_guc(struct intel_iov *iov)
{
	int err;
	const char *where;

	err = intel_iov_query_bootstrap(iov);
	if (unlikely(err)) {
		where = "bootstrap";
		goto fail;
	}
	err = intel_iov_query_config(iov);
	if (unlikely(err)) {
		where = "query config";
		goto fail;
	}
	err = intel_iov_query_runtime(iov, true);
	if (unlikely(err)) {
		where = "query runtime";
		goto fail;
	}

	return 0;

fail:
	IOV_ERROR(iov, "GuC re-init failed on %s (%pe)\n",
		  where, ERR_PTR(err));
	return err;
}
