/* gcc-attributes.h --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#ifndef GCC_ATTRIBUTES_H
#define GCC_ATTRIBUTES_H

#define NEVERNULL __attribute__ ((returns_nonnull))
#define WARNUNUSED __attribute__ ((warn_unused_result))
#define MALLOCLIKE __attribute__ ((malloc))
#define NORETURN __attribute__ ((noreturn))

#endif
