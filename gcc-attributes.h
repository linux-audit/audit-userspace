/* gcc-attributes.h -- compatibility wrappers for GCC function attributes
 * Copyright 2025 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef AUDIT_GCC_ATTRIBUTES_H
#define AUDIT_GCC_ATTRIBUTES_H

/* These macros originate in sys/cdefs.h but may be missing on some libc
 * implementations (e.g. musl). Provide fallbacks when they are undefined.
 */
#ifndef __has_attribute
# define __has_attribute(x) 0
#endif

#ifndef __attr_access
# define __attr_access(x)
#endif

#ifndef __attribute_malloc__
# define __attribute_malloc__
#endif

#ifndef __attr_dealloc
# define __attr_dealloc(dealloc, argno)
#endif

#ifndef __attr_dealloc_free
# define __attr_dealloc_free
#endif

#ifndef __attribute_const__
# define __attribute_const__
#endif

#ifndef __attribute_pure__
# define __attribute_pure__
#endif

#ifndef __nonnull
# define __nonnull(params)
#endif

#ifndef __wur
# define __wur
#endif

#endif /* AUDIT_GCC_ATTRIBUTES_H */
