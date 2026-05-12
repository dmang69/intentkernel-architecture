/*
 * IntentKernel Linux Security Module (reference interceptor)
 *
 * This interceptor denies sensitive operations unless a valid, unexpired,
 * non-revoked capability token is attached to the current task context.
 *
 * NOTE: This is a reference prototype showing hook placement and validation
 * flow. Signature verification is expected to call a kernel-resident
 * ML-DSA-87 verifier or trusted co-processor bridge.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

#define INTENTKERNEL_MAX_SIG 8192
#define INTENTKERNEL_ALG "ML-DSA-87"

struct ik_capability_token {
	u8 version;
	char algorithm[16];
	u64 token_id;
	u64 exp_ms;
	u32 uses;
	u8 ctx_hash[32];
	u32 scope;
	u32 sig_len;
	u8 sig[INTENTKERNEL_MAX_SIG];
};

/*
 * Reference token retrieval:
 * In production this should be provided by secure task credentials sourced
 * from intentd/eventscope and not regular userspace memory.
 */
static struct ik_capability_token *ik_current_token(void)
{
	return NULL;
}

/*
 * Placeholder verifier contract:
 * Returns 0 when token signature validates under ML-DSA-87.
 */
static int ik_verify_mldsa87(const struct ik_capability_token *tok)
{
	if (strncmp(tok->algorithm, INTENTKERNEL_ALG, sizeof(tok->algorithm)) != 0)
		return -EKEYREJECTED;
	/* Integrate kernel PQC verifier or enclave bridge here. */
	return 0;
}

static int ik_validate_token_scope(u32 required_scope)
{
	ktime_t now = ktime_get_real();
	u64 now_ms = ktime_to_ms(now);
	struct ik_capability_token *tok = ik_current_token();

	if (!tok)
		return -EACCES;
	if (tok->exp_ms <= now_ms)
		return -EKEYEXPIRED;
	if (tok->uses == 0)
		return -EACCES;
	if (tok->scope != required_scope)
		return -EACCES;
	if (ik_verify_mldsa87(tok) != 0)
		return -EKEYREJECTED;

	tok->uses--;
	return 0;
}

/* Scope IDs aligned to SDK primitive classes. */
enum ik_scope {
	IK_SCOPE_FILE_READ = 1,
	IK_SCOPE_FILE_WRITE = 2,
	IK_SCOPE_NETWORK_CONNECT = 3,
	IK_SCOPE_EXEC = 4,
};

static int ik_file_open(struct file *file)
{
	int required = (file->f_mode & FMODE_WRITE) ? IK_SCOPE_FILE_WRITE : IK_SCOPE_FILE_READ;
	return ik_validate_token_scope(required);
}

static int ik_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return ik_validate_token_scope(IK_SCOPE_NETWORK_CONNECT);
}

static int ik_bprm_check_security(struct linux_binprm *bprm)
{
	return ik_validate_token_scope(IK_SCOPE_EXEC);
}

static struct security_hook_list intentkernel_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, ik_file_open),
	LSM_HOOK_INIT(socket_connect, ik_socket_connect),
	LSM_HOOK_INIT(bprm_check_security, ik_bprm_check_security),
};

static int __init intentkernel_lsm_init(void)
{
	security_add_hooks(intentkernel_hooks, ARRAY_SIZE(intentkernel_hooks), "intentkernel");
	pr_info("intentkernel_lsm: initialized\n");
	return 0;
}

DEFINE_LSM(intentkernel) = {
	.name = "intentkernel",
	.init = intentkernel_lsm_init,
};

