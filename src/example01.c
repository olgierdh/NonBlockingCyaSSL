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
void __attribute__((noreturn)) DIE( const char msg[], CYASSL* cyaSSLObject );
CYASSL* closeSSL( CYASSL* cyaSSLObject, Conn_t* conn );

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
 * \brief connects
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

            return xCyaSSL_Object;
        }
    }

    return 0;
}

void print_usage( void )
{
    printf( "Usage: example_01 <server_ip> <port>\n" );
}

void DIE( const char msg[], CYASSL* cyaSSLObject )
{
    char buffer[ 256 ];

    int err = errno;

    printf( "exiting: %s\n", msg );
    strerror_r( err, buffer, sizeof( buffer ) );
    printf( "errno: %s\n", buffer );

    if( cyaSSLObject != 0 )
    {
        int cyaErr = CyaSSL_get_error( cyaSSLObject, 0 );
        CyaSSL_ERR_error_string( cyaErr, buffer );
        printf( "CyaSSLErr: %d -> %s\n", cyaErr, buffer );
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

static const char query[] = "GET /v2/feeds/2.csv?datastreams=3,4 HTTP/1.1\r\n"
"Host: api.xively.com\r\n"
"User-Agent: libxively_test_ssl_posix\r\n"
"Accept: */*\r\n"
"X-ApiKey: 1\r\n"
"\r\n";

/**
 * \main
 */
int main( const int argc, const char** argv )
{
    ( void ) argc;
    ( void ) argv;

    if( argc != 3 )
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

    len = CyaSSL_write( cyaSSLObject, query, strlen( query ) );

    if( len < ( int ) strlen( query ) )
    {
        DIE( "CyaSSL could not send data", cyaSSLObject );
    }

    printf( "Sent: %d bytes of %zu\n", len, strlen( query ) );

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
