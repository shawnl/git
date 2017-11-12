/* this is only to get definitions for memcpy(), ntohl() and htonl() */
#include "../git-compat-util.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "sha1.h"

void gnutls_SHA1_Init(gnutls_SHA_CTX *ctx)
{
	int ret;
	ret = gnutls_hash_init((void *) &ctx->handle, GNUTLS_DIG_SHA1);
	if (ret < 0)
		abort();
}

void gnutls_SHA1_Update(gnutls_SHA_CTX *ctx, const void *data, unsigned long len)
{
	gnutls_hash(ctx->handle, data, len);
}

void gnutls_SHA1_Final(unsigned char hashout[20], gnutls_SHA_CTX *ctx)
{
	gnutls_hash_deinit(ctx->handle, hashout);
}
