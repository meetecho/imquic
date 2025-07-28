/*! \file    mutex.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief    Semaphores, Mutexes and Conditions
 * \details  Implementation (based on GMutex) of a locking mechanism based on mutexes and conditions.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_MUTEX_H
#define IMQUIC_MUTEX_H

#include "../imquic/debug.h"

extern gboolean imquic_lock_debug;

/*! \brief imquic mutex implementation */
typedef GMutex imquic_mutex;
/*! \brief imquic mutex initialization */
#define imquic_mutex_init(a) g_mutex_init(a)
/*! \brief imquic static mutex initializer */
#define IMQUIC_MUTEX_INITIALIZER {0}
/*! \brief imquic mutex destruction */
#define imquic_mutex_destroy(a) g_mutex_clear(a)
/*! \brief imquic mutex lock without debug */
#define imquic_mutex_lock_nodebug(a) g_mutex_lock(a)
/*! \brief imquic mutex lock with debug (prints the line that locked a mutex) */
#define imquic_mutex_lock_debug(a) { IMQUIC_PRINT("[%s:%s:%d:lock] %p\n", __FILE__, __FUNCTION__, __LINE__, a); g_mutex_lock(a); }
/*! \brief imquic mutex lock wrapper (selective locking debug) */
#define imquic_mutex_lock(a) { if(!imquic_lock_debug) { imquic_mutex_lock_nodebug(a); } else { imquic_mutex_lock_debug(a); } }
/*! \brief imquic mutex try lock without debug */
#define imquic_mutex_trylock_nodebug(a) { ret = g_mutex_trylock(a); }
/*! \brief imquic mutex try lock with debug (prints the line that tried to lock a mutex) */
#define imquic_mutex_trylock_debug(a) { IMQUIC_PRINT("[%s:%s:%d:trylock] %p\n", __FILE__, __FUNCTION__, __LINE__, a); ret = g_mutex_trylock(a); }
/*! \brief imquic mutex try lock wrapper (selective locking debug) */
#define imquic_mutex_trylock(a) ({ gboolean ret; if(!imquic_lock_debug) { imquic_mutex_trylock_nodebug(a); } else { imquic_mutex_trylock_debug(a); } ret; })
/*! \brief imquic mutex unlock without debug */
#define imquic_mutex_unlock_nodebug(a) g_mutex_unlock(a)
/*! \brief imquic mutex unlock with debug (prints the line that unlocked a mutex) */
#define imquic_mutex_unlock_debug(a) { IMQUIC_PRINT("[%s:%s:%d:unlock] %p\n", __FILE__, __FUNCTION__, __LINE__, a); g_mutex_unlock(a); }
/*! \brief imquic mutex unlock wrapper (selective locking debug) */
#define imquic_mutex_unlock(a) { if(!imquic_lock_debug) { imquic_mutex_unlock_nodebug(a); } else { imquic_mutex_unlock_debug(a); } }

/*! \brief imquic condition implementation */
typedef GCond imquic_condition;
/*! \brief imquic condition initialization */
#define imquic_condition_init(a) g_cond_init(a)
/*! \brief imquic condition destruction */
#define imquic_condition_destroy(a) g_cond_clear(a)
/*! \brief imquic condition wait */
#define imquic_condition_wait(a, b) g_cond_wait(a, b);
/*! \brief imquic condition wait until */
#define imquic_condition_wait_until(a, b, c) g_cond_wait_until(a, b, c);
/*! \brief imquic condition signal */
#define imquic_condition_signal(a) g_cond_signal(a);
/*! \brief imquic condition broadcast */
#define imquic_condition_broadcast(a) g_cond_broadcast(a);

#endif
