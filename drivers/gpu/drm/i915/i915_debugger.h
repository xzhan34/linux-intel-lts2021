/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef __I915_DEBUGGER_H__
#define __I915_DEBUGGER_H__

#include "i915_debugger_types.h"

struct drm_device;
struct drm_file;
struct i915_drm_client;
struct i915_gem_context;
struct i915_uuid_resource;

#if IS_ENABLED(CONFIG_DRM_I915_DEBUGGER)

int i915_debugger_open_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file);

void i915_debugger_init(struct drm_i915_private *i915);
void i915_debugger_fini(struct drm_i915_private *i915);

void i915_debugger_wait_on_discovery(struct drm_i915_private * const i915);

void i915_debugger_client_register(struct i915_drm_client *client);
void i915_debugger_client_release(struct i915_drm_client *client);

void i915_debugger_client_create(const struct i915_drm_client *client);
void i915_debugger_client_destroy(const struct i915_drm_client *client);

void i915_debugger_context_create(const struct i915_gem_context *ctx);
void i915_debugger_context_destroy(const struct i915_gem_context *ctx);

void i915_debugger_uuid_create(const struct i915_drm_client *client,
			       const struct i915_uuid_resource *uuid);
void i915_debugger_uuid_destroy(const struct i915_drm_client *client,
				const struct i915_uuid_resource *uuid);

#else /* CONFIG_DRM_I915_DEBUGGER */

static inline int i915_debugger_open_ioctl(struct drm_device *dev, void *data,
					   struct drm_file *file)
{
	return -ENOTSUPP;
}

static inline void i915_debugger_init(struct drm_i915_private *i915) { }
static inline void i915_debugger_fini(struct drm_i915_private *i915) { }

static inline void i915_debugger_wait_on_discovery(struct drm_i915_private * const i915) { }

static inline void i915_debugger_client_register(struct i915_drm_client *client) { }

static inline void i915_debugger_client_release(struct i915_drm_client *client) { }

static inline void i915_debugger_client_create(const struct i915_drm_client *client) { }
static inline void i915_debugger_client_destroy(const struct i915_drm_client *client) { }

static inline void i915_debugger_context_create(const struct i915_gem_context *ctx) { }
static inline void i915_debugger_context_destroy(const struct i915_gem_context *ctx) { }

static inline void i915_debugger_uuid_create(const struct i915_drm_client *client,
					     const struct i915_uuid_resource *uuid) { }
static inline void i915_debugger_uuid_destroy(const struct i915_drm_client *client,
					      const struct i915_uuid_resource *uuid) { }

#endif /* CONFIG_DRM_I915_DEBUGGER */

#endif /* __I915_DEBUGGER_H__ */
