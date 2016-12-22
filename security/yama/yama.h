/*
 * Yama Linux Security Module
 *
 * Authors:
 *	Kees Cook <keescook@chromium.org>
 *	Djalal Harouni
 *
 * Copyright (C) 2010 Canonical, Ltd.
 * Copyright (C) 2011 The Chromium OS Authors.
 * Copyright (C) 2016 Djalal Harouni.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#define YAMA_SCOPE_DISABLED	0
#define YAMA_SCOPE_RELATIONAL	1
#define YAMA_SCOPE_CAPABILITY	2
#define YAMA_SCOPE_NO_ATTACH	3

extern int ptrace_scope;

static inline int yama_set_ptrace_scope(int value)
{
	if (value < YAMA_SCOPE_DISABLED || value > YAMA_SCOPE_NO_ATTACH)
		return -EINVAL;

	ptrace_scope = value;

	return 0;
}

static inline int yama_read_ptrace_scope(void)
{
	return ptrace_scope;
}

int yama_tasks_init(void);
void yama_tasks_clean(void);
int yama_copy_task_filter(struct task_struct *tsk);
void yama_free_task_filter(struct task_struct *tsk);
int yama_prctl_opts(struct task_struct *tsk, unsigned long arg2,
		    unsigned long arg3, unsigned long arg4);
