typedef struct {
	void *handle;
} gnutls_SHA_CTX;

void gnutls_SHA1_Init(gnutls_SHA_CTX *ctx);
void gnutls_SHA1_Update(gnutls_SHA_CTX *ctx, const void *dataIn, unsigned long len);
void gnutls_SHA1_Final(unsigned char hashout[20], gnutls_SHA_CTX *ctx);

#define platform_SHA_CTX	gnutls_SHA_CTX
#define platform_SHA1_Init	gnutls_SHA1_Init
#define platform_SHA1_Update	gnutls_SHA1_Update
#define platform_SHA1_Final	gnutls_SHA1_Final
