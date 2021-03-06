#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>

#define debug_printf( ... ) printf( __VA_ARGS__ )

#define debug_log( msg ) \
    debug_printf( "[%s@%d] - %s\r\n", __FILE__, __LINE__, msg ); \
    fflush( stdout )

#define debug_fmt( fmt, ... ) \
    debug_printf( "[%s@%d] - " fmt "\r\n", __FILE__, __LINE__, __VA_ARGS__ ); \
    fflush( stdout )

#endif // __DEBUG_H__
