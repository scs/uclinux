#ifndef PRISM2_CRYPT_H
#define PRISM2_CRYPT_H

struct hostap_crypto_ops {
	char *name;

	/* init new crypto context (e.g., allocate private data space,
	 * select IV, etc.); returns NULL on failure or pointer to allocated
	 * private data on success */
	void * (*init)(void);

	/* deinitialize crypto context and free allocated private data */
	void (*deinit)(void *priv);

	/* encrypt/decrypt return < 0 on error or number of bytes written
	 * to out_buf; len is number of bytes in in_buf */
	int (*encrypt)(u8 *buf, int len, void *priv);
	int (*decrypt)(u8 *buf, int len, void *priv);

	int (*set_key)(int idx, void *key, int len, void *priv);
	int (*get_key)(int idx, void *key, int len, void *priv);

	int (*set_key_idx)(int idx, void *priv);
	int (*get_key_idx)(void *priv);

	/* maximum number of bytes added by encryption; encrypt buf is
	 * allocated with extra_prefix_len bytes, copy of in_buf, and
	 * extra_postfix_len; encrypt need not use all this space, but
	 * the result must start at the beginning of the buffer and correct
	 * length must be returned */
	int extra_prefix_len, extra_postfix_len;
};


int hostap_register_crypto_ops(struct hostap_crypto_ops *ops);
int hostap_unregister_crypto_ops(struct hostap_crypto_ops *ops);
struct hostap_crypto_ops * hostap_get_crypto_ops(const char *name);

#endif /* PRISM2_CRYPT_H */
