/* Copyright (c) 2005-2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 * Author: Markus Gutschke
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "google/coredumper.h"
#include "linuxthreads.h"

/* Make assertion failures print more readable messages                      */
#undef strcmp
#undef strncmp
#undef strstr

/* Simple signal handler for dealing with timeouts.                          */
static jmp_buf jmpenv;
static void TimeOutHandler(int sig, siginfo_t *info, void *p) {
  siglongjmp(jmpenv, sig);
}

/* This is a really silly CPU hog, but we want to avoid creating a
 * core dump while we are executing code in libc. Depending on the
 * system environment, gdb might or might not make stack traces
 * available within libc, and that would make this unittest
 * non-deterministic.
 */
static volatile enum State { IDLE, RUNNING, DEAD } state1, state2;
static volatile unsigned int counter;
static void *Busy(void *arg) {
  volatile enum State *state = (volatile enum State *)arg;
  *state = RUNNING;
  while (*state == RUNNING) {
    counter++;
  }
  return 0;
}

/* Open the core file with "readelf", and check that all the expected
 * entries can be found. We are not checking exact numeric values, as these
 * might differ between runs, and it seems overkill recomputing them here.
 */
static void CheckWithReadElf(FILE *input, FILE *output, const char *filename,
                             const char *suffix, const char *decompress,
                             const char *args) {
  static const char *msg[] = { " ELF",
#if __BYTE_ORDER == __LITTLE_ENDIAN
                               "little"
#else
                               "big"
#endif
                               " endian", "UNIX - System V",
                               "Core file", "no sections in this file",
                               "NOTE", "no dynamic se",
                               "no relocations in this file",
                               "no unwind sections in this file",
                               "No version information found in this file",
                               "NT_PRPSINFO",
#ifndef __mips__
                               "NT_TASKSTRUCT",
#endif
                               "NT_PRSTATUS", "NT_FPREGSET",
#ifdef THREADS
                               "NT_PRSTATUS", "NT_FPREGSET",
                               "NT_PRSTATUS", "NT_FPREGSET",
#endif
                               "DONE", 0 };
  const char  **ptr;
  char buffer[4096];
  int  rc = fprintf(input,
                    "cat /proc/%d/maps &&"
                    "%s %s <\"%s%s\" >core.%d &&"
                    "readelf -a core.%d; "
                    "rm -f core.%d; "
                    "(set +x; echo DONE)\n",
                    getpid(), decompress, args, filename, suffix,
                    getpid(), getpid(), getpid());
  assert(rc > 0);

  *buffer = '\000';
  for (ptr = msg; *ptr; ptr++) {
    do {
      char *line;
      assert(strncmp(buffer, "DONE", 4));
      line = fgets(buffer, sizeof(buffer), output);
      assert(line);
      fputs(buffer, stdout);
    } while (!strstr(buffer, *ptr));
    printf("Found: %s\n", *ptr);
  }
  return;
}

/* Open the core dump with gdb, and check that the stack traces look
 * correct. Again, we are not checking for exact numeric values.
 *
 * We also extract the value of the "dummy" environment variable, and check
 * that it is correct.
 */
static void CheckWithGDB(FILE *input, FILE *output, const char *filename,
                         int *dummy, int cmp_parm) {
  volatile int cmp = cmp_parm;
  char out[4096], buffer[4096];
  char * volatile out_ptr = out;
  const char **ptr, *arg = "";
  struct sigaction sa;

#if defined(__i386__) || defined(__x86_64) || defined(__ARM_ARCH_3__) || \
    defined(__mips__)
  /* If we have a platform-specific FRAME() macro, we expect the stack trace
   * to be unrolled all the way to WriteCoreDump().
   */
  #define DUMPFUNCTION "CoreDump"
#else
  /* Otherwise, we the stack trace will start in ListAllProcessThreads.
   */
  #define DUMPFUNCTION "ListAllProcessThreads"
#endif

  /* Messages that we are looking for. "@" is a special character that
   * matches a pattern in the output, which can later be used as input
   * to gdb. "*" is a glob wildcard character.
   */
  static const char *msg[] = { "Core was generated by",
                               " @ process * *"DUMPFUNCTION,
                               "[Switching to thread * *"DUMPFUNCTION,
                               "#* *CoreDump",
                               "#@ * TestCoreDump",
                               " TestCoreDump",
                               "$1 = ",
#ifdef THREADS
                               " Busy",
                               " @ process * Busy",
                               "[Switching to thread * Busy",
                               "Busy",
                               "Busy",
#endif
                               "DONE", 0 };

  /* Commands that we are sending to gdb. All occurrences of "@" will be
   * substituted with the pattern matching the corresponding "@" character
   * in the stream of messages received.
   */
  sprintf(out,
          "gdb /proc/%d/exe \"%s\"; (set +x; echo DONE)\n"
          "info threads\n"
          "thread @\n"
          "bt 10\n"
          "up @\n"
          "print *(unsigned int *)0x%lx\n"
          "print %dU\n"
          "print %dU\n"
#ifdef THREADS
          "info threads\n"
          "thread @\n"
          "thread apply all bt 10\n"
#endif
          "quit\n",
          getpid(), filename,
          (unsigned long)dummy, *dummy, cmp);

  /* Since we are interactively driving gdb, it is possible that we would
   * indefinitely have to wait for a matching message to appear (this is
   * different from the "readelf" case, which can just read until EOF).
   * So, we have to set up a time out handler.
   */
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = TimeOutHandler;
  sa.sa_flags     = SA_RESTART|SA_SIGINFO;
  sigaction(SIGALRM, &sa, 0);

  if (setjmp(jmpenv)) {
    puts("Time out!");
    abort();
  } else {
    *buffer = '\000';
    for (ptr = msg; *ptr; ptr++) {
      /* If there is any command that does not require a pattern read from
       * the message stream, output it now.
       */
      while (*out_ptr && *out_ptr != '@') {
        int rc = putc(*out_ptr++, input);
        assert(rc >= 0);
      }
      fflush(input);
      for (;;) {
        char *line, *templ, scratch[256], isarg = 0;

        /* We should never try to read any more messages, after we have
         * already seen the final "DONE" message.
         */
        assert(strncmp(buffer, "DONE", 4));

        /* Read the next message from gdb.                                   */
        alarm(20);
        line = fgets(buffer, sizeof(buffer), output);
        alarm(0);
        assert(line);
        fputs(buffer, stdout);

        /* Extract the "$1 =" string, which we will compare later.           */
        if ((arg = strstr(buffer, "$1 = ")) != NULL) {
          cmp = atoi(arg + 5);
          arg = 0;
        }

        /* Try to match the current line against our templates.              */
        templ = strcpy(scratch, *ptr);
        for (;;) {
          /* Split the template in substring separated by "@" and "*" chars. */
          int  l = strcspn(templ, "*@");
          char c = templ[l];
          templ[l] = '\000';

          /* If we just passed a "@", remember pattern for later use.        */
          if (isarg) {
            arg = line;
            isarg = 0;
          }
          if (c == '@')
            isarg++;

          /* Check if substring of template matches somewhere in current line*/
          if ((line = strstr(line, templ)) != NULL) {
            /* Found a match. Remember arg, if any.                          */
            if (c != '@')
              *line = '\000';

            /* Advance to next pattern that needs matching.                  */
            line += strlen(templ);
          } else {
            /* No match. Break out of this loop, and read next line.         */
            templ[l] = c;
            arg = 0;
            break;
          }
          /* No more patterns. We have a successful match.                   */
          if (!c)
            goto found;
          templ[l] = c;
          templ += l + 1;
        }
      }
    found:
      /* Print matched pattern. Enter arg into command stream. Then loop.    */
      printf("Found: %s", *ptr);
      if (arg && *out_ptr == '@') {
        /* We only want to match the very last word; drop leading tokens.    */
        int rc;
        char *last = strrchr(arg, ' ');
        if (last != NULL) arg = last + 1;

        /* Enter matched data into the command stream.                       */
        rc = fputs(arg, input);
        assert(rc > 0);
        printf(" (arg = \"%s\")", arg);
        arg = 0;
        out_ptr++;
      }
      puts("");
    }
  
    assert(*dummy == cmp);
    printf("Magic marker matches %d\n", *dummy);
  }
}


/* We can test both the WriteCoreDump() and the GetCoreDump() functions
 * with the same test cases. We just need to wrap the GetCoreDump()
 * family of functions with some code that emulates the WriteCoreDump()
 * functions.
 */
static int MyWriteCompressedCoreDump(const char *file_name, size_t max_length,
                            const struct CoredumperCompressor compressors[],
                            struct CoredumperCompressor **selected_compressor){
  int                         rc = 0;
  int                         coreFd;
  struct CoredumperCompressor *comp;

  if (!max_length)
    return 0;
  coreFd = GetCompressedCoreDump(compressors, &comp);
  if (selected_compressor != NULL)
    *selected_compressor = comp;
  if (coreFd >= 0) {
    int writeFd;
    const char *suffix = "";

    if (comp != NULL && comp->compressor != NULL && comp->suffix != NULL)
      suffix = comp->suffix;

    /* scope */ {
      char extended_file_name[strlen(file_name) + strlen(suffix) + 1];
      strcat(strcpy(extended_file_name, file_name), suffix);
      writeFd = open(extended_file_name, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    }
    if (writeFd >= 0) {
      char buffer[16384];
      ssize_t len;
      while (max_length > 0 &&
             ((len = read(coreFd, buffer,
                          sizeof(buffer) < max_length
                          ? sizeof(buffer) : max_length)) > 0 ||
              (len < 0 && errno == EINTR))) {
        char *ptr = buffer;
        while (len > 0) {
          int i;
          i = write(writeFd, ptr, len);
          if (i <= 0) {
            rc = -1;
            break;
          }
          ptr        += i;
          len        -= i;
          max_length -= i;
        }
      }
      close(writeFd);
    } else {
      rc = -1;
    }
    close(coreFd);
  } else {
    rc = -1;
  }
  return rc;
}

static int MyWriteCoreDump(const char *file_name) {
  return MyWriteCompressedCoreDump(file_name, SIZE_MAX, NULL, NULL);
}

static int MyWriteCoreDumpLimited(const char *file_name, size_t max_length) {
  return MyWriteCompressedCoreDump(file_name, max_length, NULL, NULL);
}


/* Do not declare this function static, so that the compiler does not get
 * tempted to inline it. We want to be able to see some stack traces.
 */
void TestCoreDump() {
  static struct CoredumperCompressor my_compressor[] = {
  { "/NOSUCHDIR/NOSUCHFILE", 0,    0 },
  { 0,                       0,    0 }, /* Will be overwritten by test       */
  { 0,                       0,    0 } };

  int         loop, in[2], out[2], dummy, cmp, rc;
  pid_t       pid;
  FILE        *input, *output;
  pthread_t   thread;
  struct stat statBuf;
  struct CoredumperCompressor *compressor;

  /* Make stdout unbuffered. We absolutely want to see all output, even
   * if the application aborted with an assertion failure.
   */
  setvbuf(stdout, NULL, _IONBF, 0);

  /* It is rather tricky to properly call fork() from within a multi-threaded
   * application. To simplify this problem, we fork and exec /bin/bash before
   * creating the first thread.
   */
  puts("Forking /bin/bash process");
  rc = pipe(in);  assert(!rc);
  rc = pipe(out); assert(!rc);

  if ((pid = fork()) == 0) {
    int i, openmax;
    dup2(in[0],  0);
    dup2(out[1], 1);
    dup2(out[1], 2);
    openmax = sysconf(_SC_OPEN_MAX);
    for (i = 3; i < openmax; i++)
      close(i);
    fcntl(0, F_SETFD, 0);
    fcntl(1, F_SETFD, 0);
    fcntl(2, F_SETFD, 0);
    execl("/bin/bash", "bash", "-ex", NULL);
    _exit(1);
  }
  assert(pid >= 0);
  assert(!close(in[0]));
  assert(!close(out[1]));
  input  = fdopen(in[1], "w");
  output = fdopen(out[0], "r");
  setvbuf(input, NULL, _IONBF, 0);
  setvbuf(output, NULL, _IONBF, 0);

  /* Create a random value in one of our auto variables; we will later look
   * for this value by inspecting the core file with gdb.
   */
  srand(time(0));
  dummy = random();
  cmp   = ~dummy;

  /* Start some threads that should show up in our core dump; this is
   * complicated by the fact that we do not want our threads to perform any
   * system calls. So, they are busy looping and checking a volatile
   * state variable, instead.
   */
  puts("Starting threads");
  pthread_create(&thread, 0, Busy, (void *)&state1);
  pthread_create(&thread, 0, Busy, (void *)&state2);
  while (state1 != RUNNING || state2 != RUNNING) {
    usleep(100*1000);
  }

  for (loop = 0; loop < 2; loop++) {
    /* Prepare to create a core dump for the current process                 */
    puts("Writing core file to \"core-test\"");
    unlink("core-test");
  
    /* Check whether limits work correctly                                   */
    rc = (loop?MyWriteCoreDumpLimited:WriteCoreDumpLimited)("core-test", 0);
    assert(!rc);
    assert(stat("core-test", &statBuf) < 0);
    rc = (loop?MyWriteCoreDumpLimited:WriteCoreDumpLimited)("core-test", 256);
    assert(!rc);
    assert(!stat("core-test", &statBuf));
    assert(statBuf.st_size == 256);
    assert(!unlink("core-test"));
  
    /* Check wether compression works                                        */
    puts("Checking compressed core files");
    rc = (loop?MyWriteCompressedCoreDump:WriteCompressedCoreDump)
           ("core-test", SIZE_MAX, COREDUMPER_GZIP_COMPRESSED, &compressor);
    assert(!rc);
    assert(compressor);
    assert(strstr(compressor->compressor, "gzip"));
    assert(!strcmp(compressor->suffix, ".gz"));
    CheckWithReadElf(input, output, "core-test", compressor->suffix,
                     compressor->compressor, "-d");
    assert(!unlink("core-test.gz"));
  
    /* Check wether fallback to uncompressed core files works                */
    puts("Checking fallback to uncompressed core files");
    my_compressor[1].compressor = NULL; /* Disable uncompressed files        */
    rc = (loop?MyWriteCompressedCoreDump:WriteCompressedCoreDump)
           ("core-test", SIZE_MAX, my_compressor, &compressor);
    assert(rc);
    assert(!compressor->compressor);
    my_compressor[1].compressor = ""; /* Enable uncompressed files           */
    rc = (loop?MyWriteCompressedCoreDump:WriteCompressedCoreDump)
           ("core-test", SIZE_MAX, my_compressor, &compressor);
    assert(!rc);
    assert(compressor->compressor);
    assert(!*compressor->compressor);
    CheckWithReadElf(input, output, "core-test", "", "cat", "");
    assert(!unlink("core-test"));
  
    /* Create a full-size core file                                          */
    puts("Checking uncompressed core files");
    rc = (loop?MyWriteCoreDump:WriteCoreDump)("core-test");
    assert(!rc);
    CheckWithReadElf(input, output, "core-test", "", "cat", "");
    CheckWithGDB(input, output, "core-test", &dummy, cmp);

    /* Get rid of our temporary test file                                    */
    unlink("core-test");
  }

  /* Stop our threads                                                        */
  puts("Stopping threads");
  state1 = DEAD;
  state2 = DEAD;

  /* Kill bash process                                                       */
  kill(SIGTERM, pid);
  fclose(input);
  fclose(output);

  return;
}

int main(int argc, char *argv[]) {
  static int bloat[1024*1024];
  int i;

  /* This unittest parses the output from "readelf" and "gdb" in order to
   * verify that the core files look correct. And unfortunately, some of
   * the messages for these programs have been localized, so the unittest
   * cannot always find the text that it is looking for.
   * Let's just force everything back to English:
   */
  putenv(strdup("LANGUAGE=C"));
  putenv(strdup("LC_ALL=C"));

  /* Make our RSS a little bigger, so that we can test codepaths that do not
   * trigger for very small core files. Also, make sure that this data is
   * not easily compressible nor in a read-only memory segment.
   */
  for (i = 0; i < sizeof(bloat)/sizeof(int); i++) {
    bloat[i] = rand();
  }

  TestCoreDump();
  puts("PASS");
  return 0;
}
