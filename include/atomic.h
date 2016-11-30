#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <sys/types.h>
#include <pthread.h>

#define INT int

typedef struct
{
	INT counter;
	pthread_rwlock_t lock;
}atomic_t;

static inline int atomic_init(atomic_t *t)
{
	pthread_rwlock_init(&(t->lock), NULL);
	t->counter = 0;
	return 0;
}

static inline INT atomic_read(atomic_t *t)
{
	INT ret;
	if(pthread_rwlock_rdlock(&(t->lock)) != 0)
		return -1;
	ret = t->counter;
	pthread_rwlock_unlock(&(t->lock));
	return ret;
}

static inline void atomic_set(atomic_t *t, INT i)
{
	if(pthread_rwlock_wrlock(&(t->lock)) != 0) return;
	t->counter = i;
	pthread_rwlock_unlock(&(t->lock));
}

static inline INT atomic_add_return(atomic_t *t, INT i)
{
	if(pthread_rwlock_wrlock(&(t->lock)) != 0) return 0;
	t->counter += i;
	pthread_rwlock_unlock(&(t->lock));
	return t->counter;
}

#define atomic_add(t, i) (void)atomic_add_return((t), (i))

static inline INT atomic_sub_return(atomic_t *t, INT i)
{
	if(pthread_rwlock_wrlock(&(t->lock)) != 0) return 0;
	t->counter -= i;
	pthread_rwlock_unlock(&(t->lock));
	return t->counter;
}

#define atomic_sub(t, i) (void)atomic_sub_return((t), (i))

static inline void atomic_inc(atomic_t *t)
{
	atomic_add(t, 1);
}

static inline void atomic_dec(atomic_t *t)
{
	atomic_sub(t, 1);
}

#define atomic_inc_return(t) atomic_add_return(t, 1)
#define atomic_dec_return(t) atomic_sub_return(t, 1)
#define atomic_add_and_test(t, i) (atomic_add_return((t), (i)) == 0)
#define atomic_sub_and_test(t, i) (atomic_sub_return((t), (i)) == 0)
#define atomic_inc_and_test(t) (atomic_inc_return(t) == 0)
#define atomic_dec_and_test(t) (atomic_dec_return(t) == 0)

#endif
