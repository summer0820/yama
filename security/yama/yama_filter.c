/*
 * Yama Linux Security Module
 *
 * Author: Kees Cook <keescook@chromium.org>
 *         Djalal Harouni
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
#include <linux/prctl.h>
#include <linux/rhashtable.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "yama_filter.h"

/*
 * Yama filters rule:
 * We never update an already used filter we always create a new
 * one. If the filters do not match we switch to the new one.
 *
 */
struct yama_filter {
	atomic_t refcount;
	unsigned long flags;	/* flags or operations */
	struct list_head node;
	struct rcu_head rcu;
};

struct yama_task {
	atomic_t usage;		/* Usage is set only when linked into hash */

	struct rhash_head node;
	unsigned long key;

	struct task_struct *task;
	struct yama_filter *filter;

	struct work_struct clean_work;
};

static struct rhashtable yama_tasks_table;

static inline int cmp_yama_task(struct rhashtable_compare_arg *arg,
				const void *obj)
{
	const unsigned long key = *(unsigned long *)arg->key;
	const struct yama_task *ytask = obj;

	return ytask->filter == NULL ||
		atomic_read(&ytask->usage) == 0 || ytask->key != key;
}

/* TODO: optimize me */
static const struct rhashtable_params yama_tasks_params = {
	.nelem_hint = 1024,
	.head_offset = offsetof(struct yama_task, node),
	.key_offset = offsetof(struct yama_task, key),
	.key_len = sizeof(unsigned long),
	.max_size = 16384,
	.min_size = 256,
	.obj_cmpfn = cmp_yama_task,
	.automatic_shrinking = true,
};

static LIST_HEAD(yama_filters);
static DEFINE_SPINLOCK(yama_filters_lock);

static void __reclaim_yama_filters(struct work_struct *work);
static DECLARE_WORK(yama_reclaim_filters_work, __reclaim_yama_filters);

bool yama_filter_flags_match(struct yama_filter *filter, unsigned long flags)
{
	return (filter->flags == (flags & YAMA_OPTS_ALL));
}

/* Returns true if flags are set */
static inline bool yama_filter_flags_are_set(struct yama_filter *filter,
					     unsigned long flags)
{
	return (filter->flags & (flags & YAMA_OPTS_ALL)) != 0;
}

/* Returns true if flags are not set but other flags are set */
bool yama_filter_others_are_set(struct yama_filter *filter,
				unsigned long flags)
{
	unsigned long m = flags & YAMA_OPTS_ALL;

	return (filter && filter->flags != 0 && (filter->flags & m) == 0);
}

int yama_filter_get_op_flag(struct yama_filter *filter, unsigned long op)
{
	int ret = -EINVAL;

	switch (op) {
	case PR_YAMA_GET_MOD_HARDEN:
	case PR_YAMA_SET_MOD_HARDEN:
		ret = (filter->flags & YAMA_MOD_HARDEN) ? 1 :
			((filter->flags & YAMA_MOD_HARDEN_STRICT) ? 2 : 0);
		break;
	}

	return ret;
}

int yama_filter_op_to_flag(unsigned long op, unsigned long value,
			   unsigned long *flag)
{
	int ret = -EINVAL;
	unsigned long f = ~0U;

	switch (op) {
	case PR_YAMA_SET_MOD_HARDEN:
		f = (value == 1) ? YAMA_MOD_HARDEN :
			((value == 2) ? YAMA_MOD_HARDEN_STRICT : 0);
		break;
	}

	if (f != ~0U) {
		*flag = f;
		ret = 0;
	}

	return ret;
}

int yama_filter_calculate_flags(struct yama_filter *filter,
				unsigned long op, unsigned long flag,
				unsigned long *result)
{
	int ret = -EINVAL;
	unsigned long new;

	if (filter == NULL)
		return -EBADSLT;

	new = filter->flags;

	/* Special case ignore it */
	if (flag == 0) {
		ret = 0;
		goto out;
	}

	switch (op) {
	case PR_YAMA_SET_MOD_HARDEN:
		if (flag == YAMA_MOD_HARDEN_STRICT) {
			new = (new & ~YAMA_MOD_HARDEN) | YAMA_MOD_HARDEN_STRICT;
			ret = 0;
		} else if (flag == YAMA_MOD_HARDEN) {
			new |= YAMA_MOD_HARDEN;
			ret = 0;
		}
		break;
	}

out:
	if (!ret)
		*result = new;

	return ret;
}

int yama_filter_access(struct yama_filter *filter,
		       unsigned long op, unsigned long flag)
{
	int val;
	int ret = -EACCES;

	/* Return Invalid slot for now, TODO: fixme */
	if (filter == NULL)
		return -EBADSLT;

	val = yama_filter_get_op_flag(filter, op);
	if (val < 0)
		return val;

	/* We can't undo flags */
	if (val > 0 && flag == 0)
		return -EACCES;

	switch (op) {
	case PR_YAMA_SET_MOD_HARDEN:
		/* Once set to STRICT we can't re-write it */
		if (val == 2)
			return -EACCES;

		ret = 0;
		break;
	}

	return ret;
}

static inline struct yama_filter *get_yama_filter(struct yama_filter *filter)
{
	if (atomic_inc_not_zero(&filter->refcount))
		return filter;

	return NULL;
}

static void put_yama_filter(struct yama_filter *filter, bool *reclaim)
{
	if (!filter || !atomic_dec_and_test(&filter->refcount))
		return;

	if (reclaim)
		*reclaim = true;
}

struct yama_filter *init_yama_filter(unsigned long flags)
{
	struct yama_filter *filter;

	/* TODO: recheckme fixme and relax me */
	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(), current_user_ns(),
				     CAP_SYS_ADMIN) != 0)
		return ERR_PTR(-EACCES);

	filter = kzalloc(sizeof(*filter), GFP_ATOMIC);
	if (filter == NULL)
		return ERR_PTR(-ENOMEM);

	filter->flags = flags;
	atomic_set(&filter->refcount, 0);

	return filter;
}

/* Takes a ref on filter, callers should put_yama_filter() after */
struct yama_filter *lookup_yama_filter(unsigned long flags)
{
	struct yama_filter *f;
	struct yama_filter *found = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(f, &yama_filters, node) {
		if (atomic_read(&f->refcount) == 0)
			continue;

		if (yama_filter_flags_match(f, flags)) {
			found = get_yama_filter(f);
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

/* Insert yama_filter and increments ref count */
void insert_yama_filter(struct yama_filter *filter)
{
	if (!filter)
		return;

	atomic_inc(&filter->refcount);

	spin_lock(&yama_filters_lock);
	list_add_rcu(&filter->node, &yama_filters);
	spin_unlock(&yama_filters_lock);
}

/*void remove_yama_filter(struct yama_filter *filter)
{
	put_yama_filter(filter, NULL);
}*/

/* Reclaim dead entries from yama filters */
static void __reclaim_yama_filters(struct work_struct *work)
{
	struct yama_filter *filter;

	spin_lock(&yama_filters_lock);
	rcu_read_lock();
	list_for_each_entry_rcu(filter, &yama_filters, node) {
		if (atomic_read(&filter->refcount) == 0) {
			list_del_rcu(&filter->node);
			kfree_rcu(filter, rcu);
		}
	}
	rcu_read_unlock();
	spin_unlock(&yama_filters_lock);
}

void delayed_reclaim_yama_filters(bool reclaim, bool remove)
{
	if (reclaim && remove)
		schedule_work(&yama_reclaim_filters_work);
}

/*
 * negative values mean an error, 0 means not set otherwise the
 * appropriate value.
 */
int yama_task_is_op_set(struct yama_task *yama_tsk, unsigned long op)
{
	int ret = 0;
	struct yama_filter *filter;

	filter = get_yama_filter_of_task(yama_tsk);
	if (filter)
		ret = yama_filter_get_op_flag(filter, op);
	put_yama_filter_of_task(yama_tsk, false);

	return ret;
}

static struct yama_task *lookup_yama_task_unlocked(struct task_struct *tsk)
{
	return rhashtable_lookup_fast(&yama_tasks_table, tsk,
				      yama_tasks_params);
}

/*** Ref count is not taken ***/
struct yama_task *lookup_yama_task(struct task_struct *tsk)
{
	struct yama_task *ytask;

	rcu_read_lock();
	ytask = lookup_yama_task_unlocked(tsk);
	rcu_read_unlock();

	return ytask;
}

/* Insert yama_task and increments ref count on success */
int insert_yama_task(struct yama_task *yama_tsk)
{
	int ret;

	atomic_inc(&yama_tsk->usage);
	ret = rhashtable_lookup_insert_key(&yama_tasks_table,
					   yama_tsk->task, &yama_tsk->node,
					   yama_tasks_params);
	if (ret)
		atomic_dec(&yama_tsk->usage);

	return ret;
}

static void __put_yama_task(struct yama_task *yama_tsk)
{
	put_yama_filter_of_task(yama_tsk, true);
	schedule_work(&yama_tsk->clean_work);
}

struct yama_task *get_yama_task(struct task_struct *tsk)
{
	struct yama_task *ytask;

	rcu_read_lock();
	ytask = lookup_yama_task_unlocked(tsk);
	if (ytask)
		atomic_inc(&ytask->usage);
	rcu_read_unlock();

	printk("%s:%d   %p  =>  %p", __func__, __LINE__, tsk, ytask);
	return ytask;
}

void put_yama_task(struct yama_task *yama_tsk)
{
	if (yama_tsk && atomic_dec_and_test(&yama_tsk->usage))
		__put_yama_task(yama_tsk);
}

/* Reclaim dead yama tasks */
static void reclaim_yama_task(struct work_struct *work)
{
	struct yama_task *ytask = container_of(work, struct yama_task,
					       clean_work);

	WARN_ON(atomic_read(&ytask->usage) != 0);

	rhashtable_remove_fast(&yama_tasks_table, &ytask->node,
			       yama_tasks_params);
	kfree(ytask);
}

struct yama_task *init_yama_task(struct task_struct *task,
				 struct yama_filter *filter)
{
	struct yama_task *ytask;

	ytask = kzalloc(sizeof(*ytask), GFP_KERNEL | __GFP_NOWARN);
	if (ytask == NULL)
		return ERR_PTR(-ENOMEM);

	ytask->task = task;
	ytask->filter = filter;
	atomic_set(&ytask->usage, 0);
	INIT_WORK(&ytask->clean_work, reclaim_yama_task);

	return ytask;
}

int init_yama_tasks_hash(void)
{
	return rhashtable_init(&yama_tasks_table, &yama_tasks_params);
}

void destroy_yama_tasks_hash(void)
{
	rhashtable_destroy(&yama_tasks_table);
}

struct yama_filter *get_yama_filter_of_task(struct yama_task *yama_tsk)
{
	struct yama_filter *filter;

	if (!yama_tsk)
		return NULL;

	rcu_read_lock();
	filter = rcu_dereference(yama_tsk->filter);
	if (filter)
		filter = get_yama_filter(filter);
	rcu_read_unlock();

	return filter;
}

void put_yama_filter_of_task(struct yama_task *yama_tsk, bool reclaim)
{
	bool remove = false;
	struct yama_filter *filter;

	if (!yama_tsk)
		return;

	rcu_read_lock();
	filter = rcu_dereference(yama_tsk->filter);
	if (filter)
		put_yama_filter(filter, &remove);
	rcu_read_unlock();

	delayed_reclaim_yama_filters(reclaim, remove);
}

int update_yama_task_filter(struct yama_task *yama_tsk, unsigned long flags)
{
	int ret;
	struct yama_filter *new;

	new = lookup_yama_filter(flags);
	if (!new) {
		new = init_yama_filter(flags);
		if (IS_ERR(new)) {
			ret = PTR_ERR(new);
			goto out;
		}
		insert_yama_filter(new);
	}

	WARN_ON(atomic_read(&new->refcount) < 1);

	rcu_assign_pointer(yama_tsk->filter, new);
	ret = 0;
out:
	return ret;
}
