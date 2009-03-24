/* test-error.c --- Check consistency of error.c error definitions.
 * Copyright (C) 2008, 2009  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include "../src/error.c"

int
main (void)
{
  size_t i;

  for (i = 0; i < (sizeof (errors) / sizeof (errors[0])); i++)
    if (errors[i].rc != i)
      {
	printf ("%d\n", i);
	return EXIT_FAILURE;
      }

  return EXIT_SUCCESS;
}
