#include <assert.h>
#include <stdio.h>
#include <cyassl/ssl.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"

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

//function prototypes
CYASSL_CTX* init_cyaSSL( void );
int load_certificate( CYASSL_CTX* cya_ctx, const SSLCertConfig_t* cert_config );
CYASSL* connectSSL( CYASSL_CTX* cya_ctx, const Conn_t* conn );
void print_usage( void );
CYASSL* closeSSL( CYASSL* cyaSSLObject, Conn_t* conn );
char* load_file_into_memory( const char* filename, size_t* size );

/**
 * \brief   Initializes the cyassl library and creates the context
 * \return  1 if successfull <0 other way
 */
CYASSL_CTX* init_cyaSSL( void )
{
    CyaSSL_Init();

    return CyaSSL_CTX_new( CyaSSLv23_client_method() );
}

/**
 * \brief   Loads the certificate defined through the SSLCertConfig_t
 * \return  1 if successfull <0 other way
 */
int load_certificate( CYASSL_CTX* cya_ctx, const SSLCertConfig_t* cert_config )
{
    assert( cya_ctx != 0 && "CyaSSL context must not be null!" );
    assert( cert_config != 0 && "CyaSSL certificate configuration must not be null!" );
    assert( cert_config->file != 0 && "CyaSSL certificate filename must not be null!" );

    printf( "Trying to load certificate: file %s at %s dir\n", cert_config->file, cert_config->path );
    int ret = CyaSSL_CTX_load_verify_locations( cya_ctx, cert_config->file, 0 );

    printf( "Ret: %d\n", ret );

    if( ret < 0 )
    {
        return -1; //@TODO add proper cya err detection
    }

    return 1;
}

/**
 * \brief   connects
 * \return  CYASSL object if ok 0 otherway
 */
CYASSL* connectSSL( CYASSL_CTX* cya_ctx, const Conn_t* conn )
{
    assert( cya_ctx != 0 && "CyaSSL context must not be null!" );
    assert( conn != 0 && "Conn ptr must not be null!" );

    CYASSL* xCyaSSL_Object = 0;

    /* Standard Berkeley sockets connect function. */
    if( connect( conn->sock_fd, ( struct sockaddr* ) &conn->endpoint_addr, sizeof( conn->endpoint_addr ) ) == 0 )
    {
        xCyaSSL_Object = CyaSSL_new( cya_ctx );

        if( xCyaSSL_Object != NULL )
        {
            /* Associate the created CyaSSL object with the connected socket. */
            CyaSSL_set_fd( xCyaSSL_Object, conn->sock_fd );

            if( CyaSSL_connect( xCyaSSL_Object ) != SSL_SUCCESS )
            {
                return 0;
            }

            return xCyaSSL_Object;
        }

    }

    return 0;
}

void print_usage( void )
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

CYASSL* closeSSL( CYASSL* cyaSSLObject, Conn_t* conn )
{
    if( shutdown( conn->sock_fd, SHUT_RDWR ) < 0 )
    {
        printf( "Shutdown failed...\n" );
    }

    close( conn->sock_fd );

    CyaSSL_free( cyaSSLObject );

    return 0;
}

char* load_file_into_memory( const char* filename, size_t* size )
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

    CYASSL_CTX* cyaSSLContext   = 0;
    CYASSL*     cyaSSLObject    = 0;

    int len                     = 0;

    char resp[ 4096 ];
    memset( resp, 0, sizeof( resp ) );

    // SSLCertConfig_t cert_config = { argv[ 3 ], argv[ 4 ] };
    Conn_t conn_desc;

    memset( &conn_desc, 0, sizeof( conn_desc ) );
    conn_desc.sock_fd = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );

    if( conn_desc.sock_fd < 0 )
    {
        DIE( "Socket creation failed!", 0 );
    }

    conn_desc.endpoint_addr.sin_family      = AF_INET;
    conn_desc.endpoint_addr.sin_addr.s_addr = inet_addr( argv[ 1 ] );
    conn_desc.endpoint_addr.sin_port        = htons( atoi( argv[ 2 ] ) );

    cyaSSLContext = init_cyaSSL();

    if( cyaSSLContext == 0 )
    {
        DIE( "CyaSSL initialization fault...", 0 );
    }

    // disable verify cause no proper certificate
    CyaSSL_CTX_set_verify( cyaSSLContext, SSL_VERIFY_NONE, 0 );

    /*if( load_certificate( cyaSSLContext, &cert_config ) < 0 )
    {
        DIE( "CyaSSL load/verification certificate problem", 0 );
    }*/

    cyaSSLObject = connectSSL( cyaSSLContext, &conn_desc );

    if( !cyaSSLObject )
    {
        DIE( "CyaSSL could not connect properly!", 0 );
    }

    size_t size = 0;
    char* buff  = load_file_into_memory( argv[ 3 ], &size );

    if( buff == 0 )
    {
        DIE( "Could not load given file... \n", 0 );
    }

    len = CyaSSL_write( cyaSSLObject, buff, size );

    free( buff );

    if( len < ( int ) size )
    {
        DIE( "CyaSSL could not send data", cyaSSLObject );
    }

    printf( "Sent: %d bytes of %zu\n", len, size );

    len = CyaSSL_read( cyaSSLObject, resp, sizeof( resp ) );

    if( len <= 0 )
    {
        DIE( "CyaSSL could not receive data", cyaSSLObject );
    }

    printf( "Recv: %d bytes\n", len );
    printf( "Resp: %s\n", resp );

    cyaSSLObject = closeSSL( cyaSSLObject, &conn_desc );
    CyaSSL_CTX_free( cyaSSLContext ); cyaSSLContext = 0;
    CyaSSL_Cleanup();

    assert( cyaSSLObject == 0 && "Must be null!" );
    assert( cyaSSLContext == 0 && "Must be null!" );

    return 0;
}
