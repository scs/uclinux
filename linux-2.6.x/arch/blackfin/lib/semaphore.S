/*
 *  linux/arch/m68k/lib/semaphore.S
 *
 *  Copyright (C) 1996  Linus Torvalds
 *
 *  m68k version by Andreas Schwab
 *
 *  MAR/1999 -- modified to support ColdFire (gerg@snapgear.com)
 */

#include <linux/linkage.h>
#include <linux/config.h>
#include <asm/semaphore.h>

/*
 * "down_failed" is called with the eventual return address
 * in %a0, and the address of the semaphore in %a1. We need
 * to increment the number of waiters on the semaphore,
 * call "__down()", and then eventually return to try again.
 */
ENTRY(__down_failed)

ENTRY(__down_failed_interruptible)

ENTRY(__up_wakeup)

ENTRY(__down_failed_trylock)

