#include "openssl/x509.h"

int sncrypto_ossl_sk_X509_num(struct stack_st_X509 *stack) {
  return sk_X509_num(stack);
}

const X509 *sncrypto_ossl_sk_X509_value(struct stack_st_X509 *stack, int i) {
  return sk_X509_value(stack, i);
}

void sncrypto_ossl_sk_X509_free(struct stack_st_X509 *stack) {
  return sk_X509_free(stack);
}
