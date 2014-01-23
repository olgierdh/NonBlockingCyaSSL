#include <assert.h>
#include <stdio.h>
#include <cyassl/ssl.h>




/**
 * \brief   Initializes the cyassl library and creates the context
 * \return  1 if successfull <0 other way
 */
CYASSL_CTX* init_cyaSSL( void )
{
    CyaSSL_Init();

    return CyaSSL_CTX_new( CyaTLSv1_client_method() );
}

/**
 * \struct SSLCertConfig_t
 * \brief  This structure shall hold data related via the loading function
 *          should contain the information
 */
typedef struct
{
    const char* path;
    const char* file;
} SSLCertConfig_t;

/**
 * \brief   Loads the certificate defined through the SSLCertConfig_t
 * \return  1 if successfull <0 other way
 */
int load_certificate( CYASSL_CTX* cya_ctx, const SSLCertConfig_t* cert_config )
{
    assert( cya_ctx != 0 && "CyaSSL context must not be null!" );
    assert( cert_config != 0 && "CyaSSL certificate configuration must not be null!" );
    assert( cert_config->file != 0 && "CyaSSL certificate filename must not be null!" );

    if( !CyaSSL_CTX_load_verify_locations( cya_ctx, cert_config->file, cert_config->path ) )
    {
        return -1; //@TODO add proper cya err detection
    }

    return 1;
}

/**
 * \main
 */
int main( const int argc, const char* argv[] )
{
    CYASSL_CTX* cyaSSLContext = 0;
    SSLCertConfig_t cert_config = { "ca-cert.pem", 0 };

    cyaSSLContext = init_cyaSSL();

    if( cyaSSLContext == 0 )
    {
        assert( 0 && "CyaSSL initialization fault..." );
        return -1;
    }

    if( !load_certificate( cyaSSLContext, &cert_config ) )
    {
        assert( 0 && "CyaSSL load/verification certificate problem" );
        return -1;
    }

    assert( cyaSSLContext == 0 && "Must be null!" );
    return 0;
}
