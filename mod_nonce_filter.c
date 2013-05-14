#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#include <ctype.h>

static const char s_szNonceFilterName[]="NonceFilter";
char *rand_str = NULL;
module AP_MODULE_DECLARE_DATA nonce_filter_module;
typedef struct
{
	char* server_nonce;
} NonceFilterConfig;

static void *NonceFilterCreateServerConfig(apr_pool_t *p,server_rec *s)
{
	NonceFilterConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);
	return pConfig;
}

static void NonceInsertFilter(request_rec *r)
{
	NonceFilterConfig *pConfig=ap_get_module_config(r->server->module_config,
			&nonce_filter_module);


	ap_add_output_filter(s_szNonceFilterName,NULL,r,r->connection);
}

int true_random() {
	//#if APR_HAS_RANDOM
	unsigned char buf[2];
	if (apr_generate_random_bytes(buf, 2) == APR_SUCCESS)
		return (buf[0] << 8) | buf[1];
	//#endif
	apr_uint64_t time_now = apr_time_now();
	srand((unsigned int)(((time_now >> 32) ^ time_now) & 0xffffffff));
	return rand() & 0x0FFFF;
};

// make a random alpha-numeric string size characters long
void make_rstring(char *str, int size) {

	const char *cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int index;
	for(index=0; index<size; index++)
		str[index] = cs[true_random()%62];
	str[index] = 0;
}

#define BYTERANGE_FMT "%" APR_OFF_T_FMT "-%" APR_OFF_T_FMT "/%" APR_OFF_T_FMT
static apr_status_t NonceFilterOutFilter(ap_filter_t *f,
		apr_bucket_brigade *pbbIn)
{

	request_rec *r = f->r;
	NonceFilterConfig *pConfig = ap_get_module_config(r->server->module_config,
			&nonce_filter_module);

	conn_rec *c = r->connection;
	apr_bucket *pbktIn;
	apr_bucket_brigade *pbbOut;

	const char *data;
	apr_size_t len;
	char *buf;
	apr_size_t n;
	apr_bucket *pbktOut;

	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);

	if(rand_str == NULL) {
		rand_str = (char*)malloc(9*sizeof(char));
		make_rstring(rand_str, 8);
	}

	char *client_nonce_body = (char*)malloc(strlen("nonce=\"") + strlen(rand_str) + strlen("\""));
	strcpy(client_nonce_body, "nonce=\"");
	strcat(client_nonce_body, rand_str);
	strcat(client_nonce_body, "\"");

	// set headers
	apr_table_t *headers= r->headers_out;
	char *client_nonce_header= (char*)malloc(strlen("script-nonce ") + strlen(rand_str));
	strcpy(client_nonce_header, "script-nonce ");
	strcat(client_nonce_header, rand_str);

	apr_table_set(headers, "X-WebKit-CSP", client_nonce_header);
	apr_table_set(headers, "Content-Security-Policy", client_nonce_header);
	//apr_table_set(headers, "X-Content-Security-Policy", client_nonce_header);
	free(client_nonce_header);

	for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
			pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
			pbktIn = APR_BUCKET_NEXT(pbktIn))
	{
		if(APR_BUCKET_IS_EOS(pbktIn))
		{
			apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
			APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
			continue;
		}
		apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

		// check for server nonce in the body and replace it with client nonce
		const char * server_nonce = pConfig->server_nonce;
		apr_size_t new_bucket_size = len + (apr_size_t)(strlen(client_nonce_body));
		buf = apr_bucket_alloc(new_bucket_size, c->bucket_alloc);
		int index = 0;
		int iter;
		for(iter = 0; iter < len; iter++)
		{
			if(data[iter] == server_nonce[0])
			{
				int j = 0;
				for (; j < strlen(server_nonce) ; j++)
				{
					if(data[iter + j] != server_nonce[j]) {
						break;
					}
				}
				if(j == strlen(server_nonce))
				{
					iter = iter + strlen(server_nonce);
					apr_size_t i = 0;
					for(; i < strlen(client_nonce_body); i++)
					{
						buf[index++] = client_nonce_body[i];
					}
				}

			}
			buf[index++] = data[iter];
		}

		pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
				c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
	}

	apr_brigade_cleanup(pbbIn);
	return ap_pass_brigade(f->next,pbbOut);
}

static const char *NonceFilterInit(cmd_parms *cmd, void *dummy, char *arg)
{
	NonceFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,
			&nonce_filter_module);
	pConfig->server_nonce = arg;
	return NULL;
}

static const command_rec NonceFilterCmds[] =
{
	AP_INIT_TAKE1("Nonce", NonceFilterInit, NULL, OR_FILEINFO,
			"Run a nonce filter on this host"),
	{ NULL }
};

static void NonceFilterRegisterHooks(apr_pool_t *p)
{
	ap_hook_insert_filter(NonceInsertFilter,NULL,NULL,APR_HOOK_LAST);
	ap_register_output_filter(s_szNonceFilterName,NonceFilterOutFilter, NULL,
			AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA nonce_filter_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NonceFilterCreateServerConfig,
	NULL,
	NonceFilterCmds,
	NonceFilterRegisterHooks
};

