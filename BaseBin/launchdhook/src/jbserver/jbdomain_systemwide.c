#include "jbserver_global.h"
#include "jbsettings.h"
#include <libjailbreak/info.h>
#include <sandbox.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <signal.h>

#include <libjailbreak/signatures.h>
#include <libjailbreak/trustcache.h>
#include <libjailbreak/kernel.h>
#include <libjailbreak/util.h>
#include <libjailbreak/info.h>
#include <libjailbreak/primitives.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/translation.h>

#include <os/log.h>

bool gSystemwideDomainEnabled = true;
void systemwide_domain_set_enabled(bool enabled)
{
	gSystemwideDomainEnabled = enabled;
}

extern bool string_has_prefix(const char *str, const char* prefix);
extern bool string_has_suffix(const char* str, const char* suffix);

char *combine_strings(char separator, char **components, int count)
{
	if (count <= 0) return NULL;

	bool isFirst = true;

	size_t outLength = 1;
	for (int i = 0; i < count; i++) {
		if (components[i]) {
			outLength += !isFirst + strlen(components[i]);
			if (isFirst) isFirst = false;
		}
	}

	isFirst = true;
	char *outString = malloc(outLength * sizeof(char));
	*outString = 0;

	for (int i = 0; i < count; i++) {
		if (components[i]) {
			if (isFirst) {
				strlcpy(outString, components[i], outLength);
				isFirst = false;
			}
			else {
				char separatorString[2] = { separator, 0 };
				strlcat(outString, (char *)separatorString, outLength);
				strlcat(outString, components[i], outLength);
			}
		}
	}

	return outString;
}

bool systemwide_domain_allowed(audit_token_t clientToken)
{
	if (!gSystemwideDomainEnabled) {
		// While the jailbreak is hidden, we need to disable the systemwide domain
		pid_t pid = audit_token_to_pid(clientToken);
		char procPath[4*MAXPATHLEN];
		if (proc_pidpath(pid, procPath, sizeof(procPath)) <= 0) {
			return false;
		}

		if (string_has_suffix(procPath, "/Dopamine.app/Dopamine")) {
			// We still want it to be accessible by Dopamine itself though
			return true;
		}

		return false;
	}
	return true;
}

static int systemwide_get_jbroot(char **rootPathOut)
{
	*rootPathOut = strdup(jbinfo(rootPath));
	return 0;
}

static int systemwide_get_boot_uuid(char **bootUUIDOut)
{
	const char *launchdUUID = getenv("LAUNCHD_UUID");
	*bootUUIDOut = launchdUUID ? strdup(launchdUUID) : NULL;
	return 0;
}

CS_SuperBlob *siginfo_resolve_superblob(struct siginfo *siginfo, int pid, int fd)
{
	if (!siginfo) return NULL;
	if (siginfo->signature.fs_blob_size == 0) return NULL;

	size_t superblobSize = siginfo->signature.fs_blob_size;
	CS_SuperBlob *superblob = malloc(superblobSize);
	if (!superblob) return NULL;

	bool success = false;

	switch (siginfo->source) {
		case SIGNATURE_SOURCE_FILE: {
			uintptr_t superblobStart = siginfo->signature.fs_file_start + (uintptr_t)siginfo->signature.fs_blob_start;
			uintptr_t superblobEnd   = superblobStart + superblobSize;
			struct stat st = {};

        	if (fstat(fd, &st) == 0 && superblobEnd <= st.st_size && 
				lseek(fd, superblobStart, SEEK_SET) == superblobStart && 
				read(fd, superblob, superblobSize) == superblobSize) {
				success = true;
			}
			break;
		}
		case SIGNATURE_SOURCE_PROC: {
			uint64_t proc = proc_find(pid);

			if (proc && proc_vreadbuf(proc, siginfo->signature.fs_blob_start, superblob, superblobSize) == 0) {
				success = true;
			}
			break;
		}
		case SIGNATURE_SOURCE_ALLOCATION: {
			memcpy(superblob, (const void *)siginfo->signature.fs_blob_start, superblobSize);
			success = true;
			break;
		}
	}

	if (!success) {
		free(superblob);
		superblob = NULL;
	}

	return superblob;
}

int systemwide_trust_file(audit_token_t *processToken, int rfd, struct siginfo *siginfo, size_t siginfoSize)
{
	if (siginfo && siginfoSize != sizeof(struct siginfo)) return -1;

	pid_t pid = -1;
	int fd = -1;
	if (!processToken) {
		pid = 1;
		fd = dup(rfd);
	}
	else {
		pid = audit_token_to_pid(*processToken);
		struct vnode_fdinfowithpath vnodeInfo;
		int ok = proc_pidfdinfo(pid, rfd, PROC_PIDFDVNODEPATHINFO, &vnodeInfo, sizeof(vnodeInfo));
		if (ok > 0) {
			fd = open(vnodeInfo.pvip.vip_path, O_RDONLY);
		}
	}

	if (fd < 0) return -1;

	struct statfs fsb;
	int fsr = fstatfs(fd, &fsb);

	cdhash_t *cdhashes = NULL;
	uint32_t cdhashesCount = 0;

	if (siginfo) {
		CS_SuperBlob *superblob = siginfo_resolve_superblob(siginfo, pid, fd);
		if (superblob) {
			cdhash_t cdhash;
			if (code_signature_calculate_adhoc_cdhash(superblob, cdhash)) {
				if (!is_cdhash_trustcached(cdhash)) {
					cdhashes = malloc(sizeof(cdhash_t));
					cdhashesCount = 1;
					memcpy(&cdhashes[0], &cdhash, sizeof(cdhash_t));
				}
			}
			free(superblob);
		}
	}
	else {
		file_collect_untrusted_cdhashes(fd, &cdhashes, &cdhashesCount);
	}

	jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
	free(cdhashes);

	close(fd);
	return 0;
}

int systemwide_trust_file_by_path(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int r = systemwide_trust_file(NULL, fd, NULL, 0);
	close(fd);
	return r;
}

int ptrauth_disable(uint64_t proc, char* procPath) {
	if (proc) {
        uint64_t task = proc_task(proc);
        if (kread8(task + 0x348) == false) {
            uint64_t vm_map = kread_ptr(task + koffsetof(task, map));
            uint64_t pmap = kread_ptr(vm_map + koffsetof(vm_map, pmap));
            
            kwrite64(pmap + 0xC4, 0x0101010101010101);
            physwrite8(kvtophys(pmap + koffsetof(pmap, type)), 0);

            kwrite32(task + 0x348, true);
            
            uint32_t old_flags = kread32(kread_ptr(task + koffsetof(task, threads)) + 0x15E);
            uint32_t new_flags = old_flags | 1;
            kwrite8(kread_ptr(task + koffsetof(task, threads)) + 0x15E, new_flags);
        }
    }
    return 0;
}

int systemwide_process_checkin(audit_token_t *processToken, char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	pid_t pid = audit_token_to_pid(*processToken);
	char procPath[4*MAXPATHLEN];
	if (proc_pidpath(pid, procPath, sizeof(procPath)) <= 0) {
		return -1;
	}

	uint64_t proc = proc_find(pid);
	if (!proc) {
		return -1;
	}

	uint64_t task = proc_task(proc);
	if (!task) {
		return -1;
	}
	uint64_t firstThread = kread_ptr(task + koffsetof(task, threads));

	uint64_t vm_map = kread_ptr(task + koffsetof(task, map));
	if (!vm_map) {
		return -1;
	}
	uint64_t pmap = kread_ptr(vm_map + koffsetof(vm_map, pmap));
	if (!pmap) {
		return -1;
	}

	systemwide_get_jbroot(rootPathOut);
	systemwide_get_boot_uuid(bootUUIDOut);

	char *sandboxExtensionsArr[] = {
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read", JBROOT_PATH(""), 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.sandbox.executable", JBROOT_PATH(""), 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/mobile", 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/mobile/Library/Preferences", 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/Library", 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.sandbox.executable", "/Library", 0, *processToken),
        sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/mobile/Library", 0, *processToken),
        sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/mobile/Documents", 0, *processToken),
        sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/mnt", 0, *processToken),
        sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/db", 0, *processToken),
        sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", "/private/var/stash", 0, *processToken),
	};

	int sandboxExtensionsCount = sizeof(sandboxExtensionsArr) / sizeof(char *);
	*sandboxExtensionsOut = combine_strings('|', sandboxExtensionsArr, sandboxExtensionsCount);
	for (int i = 0; i < sandboxExtensionsCount; i++) {
		if (sandboxExtensionsArr[i]) {
			free(sandboxExtensionsArr[i]);
		}
	}

	bool fullyDebugged = false;

	if (string_has_prefix(procPath, "/private/var/containers/Bundle/Application") || string_has_prefix(procPath, JBROOT_PATH("/Applications")) || string_has_prefix(procPath, "/Applications") || string_has_suffix(procPath, "/Dopamine")) {
		if (jbsetting(markAppsAsDebugged)) {
			fullyDebugged = true;
		}
	}

	*fullyDebuggedOut = fullyDebugged;

	#ifdef __arm64e__
	if (strstr(procPath, "xpcproxy") == NULL) {
		ptrauth_disable(proc, procPath);
	}
	#endif

	cs_allow_invalid(proc, true);

	struct stat sb;
	if (stat(procPath, &sb) == 0) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
			uint64_t ucred = proc_ucred(proc);
			if ((sb.st_mode & (S_ISUID))) {
				kwrite32(proc + koffsetof(proc, svuid), sb.st_uid);
				kwrite32(ucred + koffsetof(ucred, svuid), sb.st_uid);
				kwrite32(ucred + koffsetof(ucred, uid), sb.st_uid);
			}
			if ((sb.st_mode & (S_ISGID))) {
				kwrite32(proc + koffsetof(proc, svgid), sb.st_gid);
				kwrite32(ucred + koffsetof(ucred, svgid), sb.st_gid);
				kwrite32(ucred + koffsetof(ucred, groups), sb.st_gid);
			}
			uint32_t flag = kread32(proc + koffsetof(proc, flag));
			if ((flag & P_SUGID) != 0) {
				flag &= ~P_SUGID;
				kwrite32(proc + koffsetof(proc, flag), flag);
			}
		}
	}
	if (__builtin_available(iOS 16.0, *)) {
		proc_allow_all_syscalls(proc);
		proc_remove_msg_filter(proc);
	}

	if (strcmp(procPath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0) {
		static bool springboardStartedBefore = false;
		if (!springboardStartedBefore) {
			springboardStartedBefore = true;
		}
		else {
			dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
				killall("/System/Library/TextInput/kbd", SIGKILL);
			});
		}
	}
	else if (string_has_suffix(procPath, "/Dopamine.app/Dopamine")) {
		uint64_t ucred = proc_ucred(proc);
		kwrite32(proc + koffsetof(proc, svuid), 0);
		kwrite32(ucred + koffsetof(ucred, svuid), 0);
		kwrite32(proc + koffsetof(proc, svgid), 0);
		kwrite32(ucred + koffsetof(ucred, svgid), 0);

		proc_csflags_set(proc, CS_PLATFORM_BINARY);
	}

#ifdef __arm64e__
	xpc_object_t customTrustObj = xpc_copy_entitlement_for_token("jb.pmap_cs.custom_trust", processToken);
	if (customTrustObj) {
		if (xpc_get_type(customTrustObj) == XPC_TYPE_STRING) {
			const char *customTrustStr = xpc_string_get_string_ptr(customTrustObj);
			uint32_t customTrust = pmap_cs_trust_string_to_int(customTrustStr);
			if (customTrust >= 2) {
				uint64_t mainCodeDir = proc_find_main_binary_code_dir(proc);
				if (mainCodeDir) {
					kwrite32(mainCodeDir + koffsetof(pmap_cs_code_directory, trust), customTrust);
				}
			}
		}
	}
#endif

	proc_rele(proc);
	return 0;
}

int systemwide_fork_fix(audit_token_t *parentToken, uint64_t childPid)
{
	int retval = 3;
	uint64_t parentPid = audit_token_to_pid(*parentToken);
	uint64_t parentProc = proc_find(parentPid);
	uint64_t childProc = proc_find(childPid);

	if (childProc && parentProc) {
		retval = 2;
		if (kread_ptr(childProc + koffsetof(proc, pptr)) == parentProc) {
			cs_allow_invalid(childProc, false);
			retval = 0;
		}
	}
	if (childProc)  proc_rele(childProc);
	if (parentProc) proc_rele(parentProc);

	return retval;
}

static int systemwide_cs_revalidate(audit_token_t *callerToken)
{
	uint64_t callerPid = audit_token_to_pid(*callerToken);
	if (callerPid > 0) {
		uint64_t callerProc = proc_find(callerPid);
		if (callerProc) {
			proc_csflags_set(callerProc, CS_VALID);
			return 0;
		}
	}
	return -1;
}

struct jbserver_domain gSystemwideDomain = {
	.permissionHandler = systemwide_domain_allowed,
	.actions = {
		{
			.handler = systemwide_get_jbroot,
			.args = (jbserver_arg[]){
				{ .name = "root-path", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		{
			.handler = systemwide_get_boot_uuid,
			.args = (jbserver_arg[]){
				{ .name = "boot-uuid", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		{
			.handler = systemwide_trust_file,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "fd", .type = JBS_TYPE_UINT64, .out = false },
				{ .name = "siginfo", .type = JBS_TYPE_DATA, .out = false },
				{ 0 },
			},
		},
		{
			.handler = systemwide_process_checkin,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "root-path", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "boot-uuid", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "sandbox-extensions", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "fully-debugged", .type = JBS_TYPE_BOOL, .out = true },
				{ 0 },
			},
		},
		{
			.handler = systemwide_fork_fix,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "child-pid", .type = JBS_TYPE_UINT64, .out = false },
				{ 0 },
			},
		},
		{
			.handler = systemwide_cs_revalidate,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ 0 },
			},
		},
		{
			.handler = jbsettings_get,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = true },
			},
		},
		{ 0 },
	},
};
