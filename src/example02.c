#include <assert.h>
#include <stdio.h>
#include <cyassl/ssl.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"

// borrowed from libxively
#include "xi_coroutine.h"

/**
 * \struct SSLCertConfig_t
 * \brief  This structure shall hold data related via the loading function
 *          should contain the information
 */
typedef struct
{
    const char* file;
    const char* path;
} SSLCertConfig_t;

/**
 * \brief To be able to pass data between functions
 */
typedef struct
{
  int                   sock_fd;
  struct sockaddr_in    endpoint_addr;
} Conn_t;

/**
 * \brief   Initializes the cyassl library and creates the context
 * \return  1 if successfull <0 other way
 */
inline static CYASSL_CTX* init_cyaSSL( void )
{
    CyaSSL_Init();

    return CyaSSL_CTX_new( CyaSSLv23_client_method() );
}

/**
 * \brief   Loads the certificate defined through the SSLCertConfig_t
 * \return  1 if successfull <0 other way
 */
inline static int load_certificate( CYASSL_CTX* cya_ctx, const SSLCertConfig_t* cert_config )
{
    assert( cya_ctx != 0 && "CyaSSL context must not be null!" );
    assert( cert_config != 0 && "CyaSSL certificate configuration must not be null!" );
    assert( cert_config->file != 0 && "CyaSSL certificate filename must not be null!" );

    debug_fmt( "Trying to load certificate: file %s at %s dir", cert_config->file, cert_config->path );
    int ret = CyaSSL_CTX_load_verify_locations( cya_ctx, cert_config->file, 0 );

    debug_fmt( "Ret: %d", ret );

    if( ret < 0 )
    {
        return -1; //@TODO add proper cya err detection
    }

    return 1;
}

inline static int myPrivateRecv( CYASSL* ssl, char* buf, int sz, void* ctx )
{
    ( void ) ssl;
    int recvd   = 0;
    int errval  = 0;
    int fd      = *( int* )ctx;

    recvd = read( fd, buf, sz );

    debug_fmt( "myPrivateRecv received - %d bytes", recvd );

    if( recvd < 0 )
    {
        errval = errno;

        debug_fmt( "errno: %d", errval );

        if( errval == EAGAIN || errval == EWOULDBLOCK )
        {
            return CYASSL_CBIO_ERR_WANT_READ;
        }
        else
        {
            return CYASSL_CBIO_ERR_GENERAL;
        }
    }
    else if( recvd == 0 )
    {
        return CYASSL_CBIO_ERR_CONN_CLOSE;
    }

    return recvd;
}

inline static int myPrivateSend( CYASSL* ssl, char* buf, int sz, void* ctx )
{
    ( void ) ssl;

    int sent    = 0;
    int errval  = 0;
    int fd      = *( int* ) ctx;

    sent = write( fd, buf, sz );

    debug_fmt( "myPrivateSend sent - %d bytes", sent );

    if( sent < 0 )
    {
        errval = errno;

        debug_fmt( "errno: %d", errval );

        if( errval == EAGAIN || errval == EWOULDBLOCK )
        {
            return CYASSL_CBIO_ERR_WANT_WRITE;
        }
        else if( errval == EPIPE )
        {
            return CYASSL_CBIO_ERR_CONN_CLOSE;
        }
        else
        {
            return CYASSL_CBIO_ERR_GENERAL;
        }
    }

    return sent;
}

inline static CYASSL* create_cyassl_object( CYASSL_CTX* cya_ctx, const Conn_t* conn )
{
    assert( cya_ctx != 0 && "CyaSSL context must not be null!" );
    assert( conn != 0 && "Conn ptr must not be null!" );

    CYASSL* xCyaSSL_Object = 0;

    xCyaSSL_Object = CyaSSL_new( cya_ctx );

    if( xCyaSSL_Object != NULL )
    {
        CyaSSL_SetIORecv( cya_ctx, myPrivateRecv );
        CyaSSL_SetIOSend( cya_ctx, myPrivateSend );

        /* Associate the created CyaSSL object with the connected socket. */
        if( CyaSSL_set_fd( xCyaSSL_Object, conn->sock_fd ) != SSL_SUCCESS )
        {
            return 0;
        }

        return xCyaSSL_Object;
    }

    return 0;
}

inline static void print_usage( void )
{
    printf( "Usage: example_01 <server_ip> <port> <filename>\n" );
}

inline static void DIE( const char msg[], CYASSL* cyaSSLObject )
{
    char* err_buffer        = 0;
    char buffer[ 256 ]      = { '\0' };

    int err = errno;

    debug_fmt( "exiting: %s", msg );
    err_buffer = strerror( err );
    debug_fmt( "errno: %s", err_buffer );

    if( cyaSSLObject != 0 )
    {
        int cyaErr = CyaSSL_get_error( cyaSSLObject, 0 );
        CyaSSL_ERR_error_string( cyaErr, buffer );
        debug_fmt( "CyaSSLErr: %d -> %s", cyaErr, buffer );
    }

    exit( -1 );
}

inline static CYASSL* closeSSL( CYASSL* cyaSSLObject, Conn_t* conn )
{
    if( shutdown( conn->sock_fd, SHUT_RDWR ) < 0 )
    {
        debug_log( "Shutdown failed..." );
    }

    close( conn->sock_fd );

    CyaSSL_free( cyaSSLObject );

    return 0;
}

inline static char* load_file_into_memory( const char* filename, size_t* size )
{
    assert( filename != 0 && "Filename must not be null!" );
    assert( size != 0 && "Pointer to size must not be null!" );

    char* ret = 0;

    FILE* fp = fopen( filename, "r" );

    if( !fp ) { goto err_handling; }

    fseek( fp, 0, SEEK_END );
    *size = ftell( fp );
    fseek( fp, 0, SEEK_SET );

    ret = malloc( *size );

    if( !ret ) { goto err_handling; }

    size_t read = fread( ret, 1, *size, fp );

    if( read != *size ) { goto err_handling; }

    fclose( fp );

    return ret;

err_handling:
    if( ret ) { free( ret ); ret = 0; }
    if( fp ) { fclose( fp ); fp = 0; }
    return 0;
}

inline static int create_non_blocking_socket()
{
    int socket_fd = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
    if( socket_fd <= 0 ) return -1;

    int flags = fcntl( socket_fd, F_GETFL, 0 );
    if( flags == -1 ) return -1;

    if( fcntl( socket_fd, F_SETFL, flags | O_NONBLOCK ) == -1 ) return -1;

    return socket_fd;
}

inline static void set_cyassl_flags( CYASSL* cya_obj )
{
    assert( cya_obj != 0 && "CyaSSL object must not be null!" );

    CyaSSL_set_using_nonblock( cya_obj, 1 );
}

typedef enum event_type
{
    FD_CAN_READ    = 0,
    FD_CAN_WRITE
} event_type_t;

typedef enum wanted_event
{
    WANT_READ = 2,
    WANT_WRITE
} wanted_event_t;

static int main_handle(
                          short*        cs
                        , CYASSL*       cya_obj
                        , Conn_t*       conn
                        , const char*   data
                        , const size_t  data_size )
{
    assert( cya_obj != 0 && conn != 0 && "cya_obj and conn must not be null at the same time!" );

    // locals that must exist through yields
    static int      state               = 0;
    static size_t   data_sent           = 0;
    static size_t   data_recv           = 0;
    static char     recv_buffer[ 256 ]  = { '\0' };
    int valopt                          = 0;
    socklen_t lon                       = sizeof( int );

    BEGIN_CORO( *cs )

    // restarted
    state = SSL_SUCCESS;

    // first part of the coroutine is about connecting to the endpoint
    {
        if( connect( conn->sock_fd, ( struct sockaddr* ) &conn->endpoint_addr, sizeof( conn->endpoint_addr ) ) == 0 )
        {
            EXIT( *cs, -1 );
        }
    }

    debug_log( "Connecting..." );
    int errval = errno;

    if( errval != EINPROGRESS )
    {
        debug_log( "Connection failed" );
        return -1;
    }

    YIELD( *cs, ( int ) WANT_WRITE );

    if( getsockopt( conn->sock_fd, SOL_SOCKET, SO_ERROR, ( void* )( &valopt ), &lon ) < 0 )
    {
        debug_fmt( "Error while getsockopt %s", strerror( errno ) );
        return -1;
    }

    if ( valopt )
    {
         debug_fmt( "Error while connecting %s", strerror( valopt ) );
         return -1;
    }

    debug_fmt( "Connected! state = %d", state );

    // part two is actually to do the ssl handshake
    {
        do
        {
            if( state == SSL_ERROR_WANT_READ )
            {
                YIELD( *cs, ( int ) WANT_READ );
            }

            if( state == SSL_ERROR_WANT_WRITE )
            {
                YIELD( *cs, ( int ) WANT_WRITE );
            }

            debug_log( "Connecting SSL..." );
            int ret = CyaSSL_connect( cya_obj );

            state = ret <= 0 ? CyaSSL_get_error( cya_obj, ret ) : ret;
            debug_fmt( "Connecting SSL state [%d][%d][%d]", state, ret, ( int ) SSL_SUCCESS );

        } while( state != SSL_SUCCESS && ( state == SSL_ERROR_WANT_READ || state == SSL_ERROR_WANT_WRITE ) );

        // we've connected or failed
        if( state != SSL_SUCCESS )
        {
            // something went wrong
            EXIT( *cs, -1 );
        }
    }

    // part three sending a message
    {
        data_sent = 0;

        do
        {
            do
            {
                if( state == SSL_ERROR_WANT_READ )
                {
                    YIELD( *cs, ( int ) WANT_READ );
                }

                if( state == SSL_ERROR_WANT_WRITE )
                {
                    YIELD( *cs, ( int ) WANT_WRITE );
                }

                size_t offset       = data_sent;
                size_t size_left    = data_size - data_sent;

                debug_fmt( "Sending SSL... data_size = [%zu], data_sent = [%zu]", data_size, data_sent );
                int ret             = CyaSSL_write( cya_obj, data + offset, size_left );
                state               = ret <= 0 ? CyaSSL_get_error( cya_obj, ret ) : SSL_SUCCESS;
                debug_fmt( "Sending SSL state state = [%d], ret = [%d]", state, ret );

                if( ret > 0 ) { data_sent += ret; }
            } while( data_sent < data_size && state == SSL_SUCCESS );
        } while( state != SSL_SUCCESS && ( state == SSL_ERROR_WANT_READ || state == SSL_ERROR_WANT_WRITE ) );

        if( state != SSL_SUCCESS )
        {
            debug_log( "Exiting" );
            EXIT( *cs, -1 );
        }
    }

    // part four receive
    {
        do
        {
            do
            {
                if( state == SSL_ERROR_WANT_READ )
                {
                    YIELD( *cs, ( int ) WANT_READ );
                }

                if( state == SSL_ERROR_WANT_WRITE )
                {
                    YIELD( *cs, ( int ) WANT_WRITE );
                }

                int ret     = CyaSSL_read( cya_obj, recv_buffer, sizeof( recv_buffer ) - 1 );
                state       = ret <= 0 ? CyaSSL_get_error( cya_obj, ret ) : SSL_SUCCESS;

                if( ret > 0 )
                {
                    recv_buffer[ ret ] = '\0';
                    debug_fmt( "<<<%s>>>", recv_buffer );
                    debug_fmt( "Received SSL... size = [%d], state = [%d]", ret, state );
                    data_recv = ret;
                }
            } while( data_recv == sizeof( recv_buffer ) - 1 && state == SSL_SUCCESS );
        } while( state != SSL_SUCCESS && ( state == SSL_ERROR_WANT_READ || state == SSL_ERROR_WANT_WRITE ) );

        if( state != SSL_SUCCESS )
        {
            EXIT( *cs, -1 );
        }
    }

    RESTART( *cs, 0 );

    END_CORO()
}

/**
 * \main
 */
int main( const int argc, const char** argv )
{
    ( void ) argc;
    ( void ) argv;

    if( argc != 4 )
    {
        print_usage();
        exit( 1 );
    }

    wanted_event_t wanted_event         = WANT_READ;

    short cs                    = 0;

    CYASSL_CTX* cyaSSLContext   = 0;
    CYASSL*     cyaSSLObject    = 0;

    struct timeval timeout;
    memset( &timeout, 0, sizeof( struct timeval ) );

    int max_fd                  = 0;

    fd_set r_master_set, r_working_set, w_master_set, w_working_set;
    FD_ZERO( &r_master_set );
    FD_ZERO( &w_master_set );
    FD_ZERO( &r_working_set );
    FD_ZERO( &w_working_set );

    // --------------------------- initialization ---------------------------------

    Conn_t conn_desc;
    memset( &conn_desc, 0, sizeof( conn_desc ) );

    char resp[ 4096 ];
    memset( resp, 0, sizeof( resp ) );

    conn_desc.sock_fd = create_non_blocking_socket();
    if( conn_desc.sock_fd < 0 ) DIE( "Socket creation failed!", 0 );

    conn_desc.endpoint_addr.sin_family      = AF_INET;
    conn_desc.endpoint_addr.sin_addr.s_addr = inet_addr( argv[ 1 ] );
    conn_desc.endpoint_addr.sin_port        = htons( atoi( argv[ 2 ] ) );

    cyaSSLContext = init_cyaSSL();
    if( cyaSSLContext == 0 ) DIE( "CyaSSL initialization fault...", 0 );

    // disable verify cause no proper certificate
    CyaSSL_CTX_set_verify( cyaSSLContext, SSL_VERIFY_NONE, 0 );

    cyaSSLObject = create_cyassl_object( cyaSSLContext, &conn_desc );
    if( !cyaSSLObject ) DIE( "CyaSSLObject not created properly!", 0 );

    set_cyassl_flags( cyaSSLObject );

    max_fd = conn_desc.sock_fd;

    FD_SET( conn_desc.sock_fd, &r_master_set );
    FD_SET( conn_desc.sock_fd, &w_master_set );

    // five minutes timeout
    timeout.tv_sec  = 3 * 60;
    timeout.tv_usec = 0;

    // --------------------------- main non blocking event processing loop ---------------------------------

    size_t  data_size   = 0;
    char*   data        = load_file_into_memory( argv[ 3 ], &data_size );
    if( data == 0 ) DIE( "Could not load given file... \n", 0 );

    // almost endless loop
    for( ; ; )
    {
        debug_log( "main_handle..." );
        int ret = main_handle( &cs, cyaSSLObject, &conn_desc, data, data_size );
        debug_log( "main_handle done!" );

        if( ret == -1 ) DIE( "error on main_handle...", cyaSSLObject );
        if( ret ==  0 ) break;

        wanted_event = ret;

        memcpy( &r_working_set, &r_master_set, sizeof( fd_set ) );
        memcpy( &w_working_set, &w_master_set, sizeof( fd_set ) );

        debug_fmt( "select... [%d]", ( int ) wanted_event );

        int s_ret = select(
                  max_fd + 1
                , wanted_event == WANT_READ ? &r_working_set : NULL
                , wanted_event == WANT_WRITE ? &w_working_set : NULL
                , NULL
                , &timeout );

        debug_fmt( "select done [%d]", s_ret );

        if( s_ret < 0 )     DIE( "error on select...", cyaSSLObject );
        if( s_ret == 0 )    DIE( "timeout on select...", cyaSSLObject );
    }

    free( data );

    cyaSSLObject = closeSSL( cyaSSLObject, &conn_desc );
    CyaSSL_CTX_free( cyaSSLContext ); cyaSSLContext = 0;
    CyaSSL_Cleanup();

    assert( cyaSSLObject == 0 && "Must be null!" );
    assert( cyaSSLContext == 0 && "Must be null!" );

    return 0;
}
