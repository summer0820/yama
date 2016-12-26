/*
 * Yama Linux Security Module
 *
 * Author: Djalal Harouni
 *
 * Copyright (C) 2010 Canonical, Ltd.
 * Copyright (C) 2011 The Chromium OS Authors.
 * Copyright (c) 2016 Djalal Harouni
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/string_helpers.h>
#include <linux/task_work.h>
#include <linux/prctl.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "yama_filter.h"

int yama_tasks_init(void)
{
	return init_yama_tasks_hash();
}

void yama_tasks_clean(void)
{
	return destroy_yama_tasks_hash();
}

/* Returns NULL if it can't find a matching filter */
static struct yama_filter *get_matching_task_filter(struct yama_task *yama_tsk,
						    unsigned long op,
						    unsigned long value)
{
	int ret = 0;
	struct yama_filter *old = NULL;

	old = get_yama_filter_of_task(yama_tsk);
	if (!old)
		return NULL;

	ret = yama_filter_get_op_flag(old, op);
	if (ret <= 0) {
		put_yama_filter_of_task(yama_tsk, false);
		return NULL;
	}

	return old;
}

/* caller have to do put_yama_filter_of_task() */
static struct yama_filter *give_me_yama_filter(struct yama_tsk *yama_tsk,
					       unsigned long op,
					       unsigned long value)
{
	int err = 0;
	struct yama_filter *old;
	struct yama_filter *new = NULL;

	old = get_matching_task_filter(yama_tsk, op, value);
	if (old)
		return old;

	new = lookup_yama_filter((u8) value);
	if (new)
		goto link;

	new = init_yama_filter((u8) value);
	if (IS_ERR(new))
		return new;

	/* TODO: link me here ** Still not linked */
	atomic_inc(&new->refcount);
	return new;
}

/* On success, callers have to do put_yama_task() */
static struct yama_task *give_me_yama_task(struct task_struct *tsk)
{
	struct yama_task *ytask;

	ytask = get_yama_task(tsk);
	if (ytask)
		return ytask;

	ytask = init_yama_task(tsk, NULL);
	if (IS_ERR(ytask))
		return ytask;

	/* Mark it as active */
	ret = insert_yama_task(ytask);
	if (ret) {
		kfree(ytask);
		return ERR_PTR(ret);
	}

	return ytask;
}

static int yama_set_mod_harden(struct task_struct *tsk, unsigned long value)
{
	int ret;
	struct yama_task *ytask;
	struct yama_filter *filter;

	ret = yama_op_value_to_flag(
	/*
	ret = yama_filter_validate_flags(value);
	if (ret < 0)
		return ret;
	*/


	/* Get Yama task */
	ytask = give_me_yama_task(tsk);
	if (IS_ERR(ytask))
		return PTR_ERR(ytask);

	/* Get Yama filter */
	filter = give_me_yama_filter(ytask, YAMA_GET_MOD_HARDEN);
	if (IS_ERR(filter)) {
		ret = PTR_ERR(filter);
		goto out;
	}

	insert_yama_filter(filter);

	/* TODO: ignore errors of yama_task already exists */
	ret = insert_yama_task(ytask);
	if (ret)
		goto err_mem;

	put_yama_filter_of_task(
	put_yama_task(ytask);

	return 0;

out:
	put_yama_task(ytask);
	return ret;
}

static int yama_get_op_value(struct task_struct *tsk, unsigned long arg)
{
	int ret;
	struct yama_task *ytask;

	ytask = get_yama_task(tsk);
	if (!ytask)
		return -EINVAL;

	ret = yama_task_is_op_set(ytask, arg);
	put_yama_task(ytask);

	return ret;
}

int yama_copy_task_filter(struct task_struct *tsk)
{
	int ret = 0;
	struct yama_filter *filter;
	struct yama_task *yparent;
	struct yama_task *ytask = NULL;

	yparent = get_yama_task(current);

	/* Parent does not have a yama filter context, nothing to do */
	if (yparent == NULL)
		return ret;

	filter = get_yama_filter_of_task(yparent);

	ytask = init_yama_task(tsk, filter);
	if (IS_ERR(ytask)) {
		ret = PTR_ERR(ytask);
		goto out;
	}

	ret = insert_yama_task(ytask);
	if (ret)
		kfree(ytask);

out:
	put_yama_filter_of_task(yparent, false);
	put_yama_task(yparent);
	return ret;
}

void yama_free_task_filter(struct task_struct *tsk)
{
	struct yama_task *ytask;

	ytask = lookup_yama_task(tsk);
	if (!ytask)
		return;

	put_yama_task(ytask);
}

int yama_prctl_opts(struct task_struct *tsk, unsigned long arg2,
		    unsigned long arg3, unsigned long arg4)
{
	int ret = -EINVAL;

	switch (arg2) {
	case PR_YAMA_SET_MOD_HARDEN:
		ret = yama_set_mod_harden(tsk, arg3);
		break;
	case PR_YAMA_GET_MOD_HARDEN:
		ret = yama_get_op_value(tsk, PR_YAMA_GET_MOD_HARDEN);
		break;
	}

	return ret;
}
