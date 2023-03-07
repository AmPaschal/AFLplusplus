/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <sys/time.h>
#include <signal.h>
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

#include "cmplog.h"

#ifdef PROFILING
u64 time_spent_working = 0;
#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot))
fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv, u32 timeout) {

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}


// fsrv_run_result_t __attribute__((hot))
// fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv, u32 timeout) {

// #ifdef PROFILING
//   static u64      time_spent_start = 0;
//   struct timespec spec;
//   if (time_spent_start) {

//     u64 current;
//     clock_gettime(CLOCK_REALTIME, &spec);
//     current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
//     time_spent_working += (current - time_spent_start);

//   }

// #endif

//   fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

// #ifdef PROFILING
//   clock_gettime(CLOCK_REALTIME, &spec);
//   time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
// #endif

//   return res;

// }

// void write_buffer_to_file(char *buffer, size_t buffer_size) {
//     // Get current time
//     time_t current_time = time(NULL);

//     // Generate timestamp string
//     char timestamp[20];
//     strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&current_time));

//     // Create filename with timestamp appended
//     char filename[256];
//     snprintf(filename, sizeof(filename), "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/rough/output_%s.txt", timestamp);

//     // Open the file for writing
//     FILE *fp = fopen(filename, "w");
//     if (fp == NULL) {
//         perror("Error opening file for writing");
//         exit(EXIT_FAILURE);
//     }

//     // Write the buffer to the file
//     fwrite(buffer, buffer_size, 1, fp);

//     // Close the file
//     fclose(fp);
// }

// /* Write modified data to file for testing. If afl->fsrv.out_file is set, the
//    old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
//    rewound and truncated.
//    When calling the postprocessor, new_mem represents the input from the queue
//    while new_buf represents the output from the postprocessor */

// int hex_to_int(char c) {
//     if (c >= '0' && c <= '9') {
//         return c - '0';
//     } else if (c >= 'a' && c <= 'f') {
//         return c - 'a' + 10;
//     } else if (c >= 'A' && c <= 'F') {
//         return c - 'A' + 10;
//     } else {
//         return -1;
//     }
// }

// char* hex_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
//   size_t hex_string_size = input_length * 2 + 1;
//   char *encoded_data = malloc(hex_string_size);

//   for (size_t i = 0; i < input_length; i++) {
//       snprintf(encoded_data + (i * 2), hex_string_size - (i * 2), "%02x", data[i]);
//   }
//   encoded_data[hex_string_size - 1] = '\0';

//   printf("encoded_data: %s hex_string_size: %ld input_length: %ld \n", encoded_data, hex_string_size, input_length);

//   *output_length = hex_string_size - 1;

//   return encoded_data;
// }

// unsigned char* hex_decode(const char* data, size_t input_length, size_t* output_length) {

//   if (input_length % 2 != 0) {
//       *output_length = 0;
//       return NULL;
//   }

//   size_t decoded_data_size = input_length / 2;
//   unsigned char *decoded_data = malloc(decoded_data_size);

//   for (size_t i = 0; i < decoded_data_size; i++) {
//       int hi = hex_to_int(data[i * 2]);
//       int lo = hex_to_int(data[i * 2 + 1]);
//       if (hi == -1 || lo == -1) {
//           *output_length = 0;
//           return NULL;
//       }
//       decoded_data[i] = (unsigned char)((hi << 4) | lo);
//   }

//   *output_length = decoded_data_size;

//   return decoded_data;
// }


// u32 __attribute__((hot))
// write_to_testcase(afl_state_t *afl, void **mem, u32 len, u32 fix) {

//   if (unlikely(afl->custom_mutators_count)) {

//     ssize_t new_size = len;
//     u8     *new_mem = *mem;
//     u8     *new_buf = NULL;

//     u8 min_length = new_mem[2];
//     u8 max_length = new_mem[3];

//     //printf("Fuzz seed min length: %d \n", min_length);
//     //printf("Fuzz seed max length: %d \n", max_length);

//     if (unlikely(new_size < min_length)) {

//       return 0;

//     } else if (unlikely(new_size > max_length)) {

//       // new_size = max_length;

//     }


//     printf("len: %d new_size: %d max_length: %d \n", len, new_size, max_length);

//     // Call python script to postprocess 
//     char command[1024];
//     char* encoded_buf = hex_encode(new_mem, new_size, &new_size);
//     snprintf(command, sizeof(command), "python3 /home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/example.py %s", encoded_buf);
//     free(encoded_buf);

//     // Open a pipe to the command and read its output
//     FILE *fp = popen(command, "r");
//     if (fp == NULL) {
//         perror("Error opening pipe to post-processor");
//         return 0;
//     }

//     // Read the output of the command into a buffer
//     char output_buf[1024];
//     size_t output_len = fread(output_buf, 1, sizeof(output_buf), fp);

//     // Close the pipe
//     int status = pclose(fp);
//     if (status == -1) {
//         perror("Error closing pipe to command");
//         return 0;
//     } else if (WIFEXITED(status)) {
//         if (WEXITSTATUS(status) != 0) {
//             fprintf(stderr, "Command %s exited with non-zero status %d\n", command, WEXITSTATUS(status));
//             return 0;
//         }
//     } else if (WIFSIGNALED(status)) {
//         fprintf(stderr, "Command killed by signal %d\n", WTERMSIG(status));
//         return 0;
//     } else {
//         fprintf(stderr, "Command terminated abnormally\n");
//         return 0;
//     }

//     if (output_len == sizeof(output_buf)) {
//         fprintf(stderr, "Output buffer too small for command output\n");
//         return 0;
//     } else if (output_len == 0) {
//         fprintf(stderr, "Command produced no output\n");
//         return 0;
//     } else {
//         // We assume we read the hex string from stdout, so we need to add a null terminator
//         output_buf[output_len] = '\0';
//     }

//     // Decode the output from base64 and store it in new_buf (remember to free it later)
//     new_buf = hex_decode(output_buf, output_len, &new_size);

//     // Display a success message
//     printf("Successfully post-processed data with new size: %d and buffer: %p\n", new_size, new_buf);

//     // Do something with new_buf

//     if (unlikely(!new_buf || new_size <= 0)) {

//       new_size = 0;
//       new_buf = new_mem;
//       // FATAL("Custom_post_process failed (ret: %lu)", (long
//       // unsigned)new_size);

//     } else {

//       new_mem = new_buf;
//       write_buffer_to_file(new_mem, new_size);

//     }

    



//     // LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

//     //   if (el->afl_custom_post_process) {

//     //     new_size =
//     //         el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

//     //     if (unlikely(!new_buf || new_size <= 0)) {

//     //       new_size = 0;
//     //       new_buf = new_mem;
//     //       // FATAL("Custom_post_process failed (ret: %lu)", (long
//     //       // unsigned)new_size);

//     //     } else {

//     //       new_mem = new_buf;

//     //     }

//     //   }

//     // });

//     if (unlikely(!new_size)) {

//       // perform dummy runs (fix = 1), but skip all others
//       if (fix) {

//         new_size = len;

//       } else {

//         return 0;

//       }

//     }

//     if (unlikely(new_size < afl->min_length && !fix)) {

//       new_size = afl->min_length;

//     } else if (unlikely(new_size > afl->max_length)) {

//       new_size = afl->max_length;

//     }

//     /* 
//     I will be making some changes here so that the buffer returned from the postprocessor
//     is not propagated back to the calling function.
//     1. If the postprocessor returns a buffer, the returned buffer will be written to the file.
//     2. The original buffer wont be updated and the original length would be returned.
//      */

//     // if (new_mem != *mem) { *mem = new_mem; }

//     /* everything as planned. use the potentially new data. */
//     afl_fsrv_write_to_testcase(&afl->fsrv, new_mem, new_size);
//     //len = new_size;

//     // Free the memory used by new_buf
//     free(new_buf);


//   } else {

//     if (unlikely(len < afl->min_length && !fix)) {

//       len = afl->min_length;

//     } else if (unlikely(len > afl->max_length)) {

//       len = afl->max_length;

//     }

//     /* boring uncustom. */
//     afl_fsrv_write_to_testcase(&afl->fsrv, *mem, len);

//   }

// #ifdef _AFL_DOCUMENT_MUTATIONS
//   s32  doc_fd;
//   char fn[PATH_MAX];
//   snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", afl->out_dir,
//            afl->document_counter++,
//            describe_op(afl, 0, NAME_MAX - strlen("000000000:")));

//   if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION)) >=
//       0) {

//     if (write(doc_fd, *mem, len) != len)
//       PFATAL("write to mutation file failed: %s", fn);
//     close(doc_fd);

//   }

// #endif

//   return len;

// }



/* Write modified data to file for testing. If afl->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
   rewound and truncated.
   When calling the postprocessor, new_mem represents the input from the queue
   while new_buf represents the output from the postprocessor */

u32 __attribute__((hot))
write_to_testcase(afl_state_t *afl, void **mem, u32 len, u32 fix) {

  if (unlikely(afl->custom_mutators_count)) {

    ssize_t new_size = len;
    u8     *new_mem = *mem;
    u8     *new_buf = NULL;

    u8 min_length = new_mem[2];
    u8 max_length = new_mem[3];

    //printf("Fuzz seed min length: %d \n", min_length);
    //printf("Fuzz seed max length: %d \n", max_length);

    if (unlikely(new_size < min_length)) {

      new_size = min_length;

    } else if (unlikely(new_size > max_length)) {

      new_size = max_length;

    }

    // Write new_mem to file

    FILE *fp = (FILE *) afl->file_in;
    if (ftruncate(fp->_fileno, 0) == -1) {
        // handle error
        printf("Truncating in file failed with errno %d...\n", errno);
        return 0;
    }
    fseek(fp, 0, SEEK_SET);
    fwrite(new_mem, 1, new_size, fp);
    // fclose(fp);

    // memcpy(afl->mmap_in, new_mem, new_size);

    // Call python script to postprocess
    const char* pd_command = "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/example.py";
    const char* pd_path = "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/";


    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "python3 %s %s %s", pd_command, afl->seed_file, pd_path);


    system(cmd);
    
    // Read content of the postprocessed file to new_buf
    FILE *fp2 = (FILE *) afl->file_out;
    fseek(fp2, 0, SEEK_END);
    new_size = ftell(fp2);
    fseek(fp2, 0, SEEK_SET);  /* same as rewind(f); */
    new_buf = malloc(new_size);
    fread(new_buf, new_size, 1, fp2);

     if (ftruncate(fp2->_fileno, 0) == -1) {
        // handle error
        printf("Truncating out file failed...\n");
        return 0;
    }
    // fclose(fp2);

    // struct stat st;

    // // Get information about the file
    // if (stat("/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/original_fuzz_seed.pd", &st) == -1) {
    //     printf("Calling stat failed...\n");
    //     exit(EXIT_FAILURE);
    // }

    // new_size = st.st_size;
    // new_buf = malloc(new_size);
    // memcpy(new_buf, afl->mmap_out, new_size);

    // const int SIZE = 4096;

    // // Reset the memory locations
    // memset(afl->mmap_in, 0, SIZE);
    // memset(afl->mmap_out, 0, SIZE);


    if (unlikely(!new_buf || new_size <= 0)) {

      new_size = 0;
      new_buf = new_mem;
      // FATAL("Custom_post_process failed (ret: %lu)", (long
      // unsigned)new_size);

    } else {

      new_mem = new_buf;

    }



    // LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

    //   if (el->afl_custom_post_process) {

    //     new_size =
    //         el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

    //     if (unlikely(!new_buf || new_size <= 0)) {

    //       new_size = 0;
    //       new_buf = new_mem;
    //       // FATAL("Custom_post_process failed (ret: %lu)", (long
    //       // unsigned)new_size);

    //     } else {

    //       new_mem = new_buf;

    //     }

    //   }

    // });

    if (unlikely(!new_size)) {

      // perform dummy runs (fix = 1), but skip all others
      if (fix) {

        new_size = len;

      } else {

        return 0;

      }

    }

    if (unlikely(new_size < afl->min_length && !fix)) {

      new_size = afl->min_length;

    } else if (unlikely(new_size > afl->max_length)) {

      new_size = afl->max_length;

    }

    /* 
    I will be making some changes here so that the buffer returned from the postprocessor
    is not propagated back to the calling function.
    1. If the postprocessor returns a buffer, the returned buffer will be written to the file.
    2. The original buffer wont be updated and the original length would be returned.
     */

    // if (new_mem != *mem) { *mem = new_mem; }

    /* everything as planned. use the potentially new data. */
    afl_fsrv_write_to_testcase(&afl->fsrv, new_mem, new_size);
    //len = new_size;

  } else {

    if (unlikely(len < afl->min_length && !fix)) {

      len = afl->min_length;

    } else if (unlikely(len > afl->max_length)) {

      len = afl->max_length;

    }

    /* boring uncustom. */
    afl_fsrv_write_to_testcase(&afl->fsrv, *mem, len);

  }

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32  doc_fd;
  char fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", afl->out_dir,
           afl->document_counter++,
           describe_op(afl, 0, NAME_MAX - strlen("000000000:")));

  if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION)) >=
      0) {

    if (write(doc_fd, *mem, len) != len)
      PFATAL("write to mutation file failed: %s", fn);
    close(doc_fd);

  }

#endif

  return len;

}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
                           u32 skip_len) {

  s32 fd = afl->fsrv.out_fd;
  u32 tail_len = len - skip_at - skip_len;

  /*
  This memory is used to carry out the post_processing(if present) after copying
  the testcase by removing the gaps. This can break though
  */
  u8 *mem_trimmed = afl_realloc(AFL_BUF_PARAM(out_scratch), len - skip_len + 1);
  if (unlikely(!mem_trimmed)) { PFATAL("alloc"); }

  ssize_t new_size = len - skip_len;
  u8     *new_mem = mem;

  bool post_process_skipped = true;

  if (unlikely(afl->custom_mutators_count)) {

    u8 *new_buf = NULL;
    new_mem = mem_trimmed;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        // We copy into the mem_trimmed only if we actually have custom mutators
        // *with* post_processing installed

        if (post_process_skipped) {

          if (skip_at) { memcpy(mem_trimmed, (u8 *)mem, skip_at); }

          if (tail_len) {

            memcpy(mem_trimmed + skip_at, (u8 *)mem + skip_at + skip_len,
                   tail_len);

          }

          post_process_skipped = false;

        }

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf && new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

  }

  if (likely(afl->fsrv.use_shmem_fuzz)) {

    if (!post_process_skipped) {

      // If we did post_processing, copy directly from the new_mem buffer

      memcpy(afl->fsrv.shmem_fuzz, new_mem, new_size);

    } else {

      memcpy(afl->fsrv.shmem_fuzz, mem, skip_at);

      memcpy(afl->fsrv.shmem_fuzz + skip_at, mem + skip_at + skip_len,
             tail_len);

    }

    *afl->fsrv.shmem_fuzz_len = new_size;

#ifdef _DEBUG
    if (afl->debug) {

      fprintf(
          stderr, "FS crc: %16llx len: %u\n",
          hash64(afl->fsrv.shmem_fuzz, *afl->fsrv.shmem_fuzz_len, HASH_CONST),
          *afl->fsrv.shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", afl->fsrv.shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", (u8)((u8 *)mem)[i]);
      fprintf(stderr, "\n");

    }

#endif

    return;

  } else if (unlikely(!afl->fsrv.use_stdin)) {

    if (unlikely(afl->no_unlink)) {

      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC,
                DEFAULT_PERMISSION);

    } else {

      unlink(afl->fsrv.out_file);                         /* Ignore errors. */
      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL,
                DEFAULT_PERMISSION);

    }

    if (fd < 0) { PFATAL("Unable to create '%s'", afl->fsrv.out_file); }

  } else {

    lseek(fd, 0, SEEK_SET);

  }

  if (!post_process_skipped) {

    ck_write(fd, new_mem, new_size, afl->fsrv.out_file);

  } else {

    ck_write(fd, mem, skip_at, afl->fsrv.out_file);

    ck_write(fd, mem + skip_at + skip_len, tail_len, afl->fsrv.out_file);

  }

  if (afl->fsrv.use_stdin) {

    if (ftruncate(fd, new_size)) { PFATAL("ftruncate() failed"); }
    lseek(fd, 0, SEEK_SET);

  } else {

    close(fd);

  }

}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  u8 fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
     first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us, diff_us;
  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;

  if (unlikely(afl->shm.cmplog_mode)) { q->exec_cksum = 0; }

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz) {

    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!afl->fsrv.fsrv_pid) {

    if (afl->fsrv.cmplog_binary &&
        afl->fsrv.init_child_func != cmplog_exec_child) {

      FATAL("BUG in afl-fuzz detected. Cmplog mode not set correctly.");

    }

    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;

    }

  }

  /* we need a dummy run if this is LTO + cmplog */
  if (unlikely(afl->shm.cmplog_mode)) {

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

  }

  if (q->exec_cksum) {

    memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);
    hnb = has_new_bits(afl, afl->virgin_bits);
    if (hnb > new_bits) { new_bits = hnb; }

  }

  start_us = get_cur_time_us();

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    if (unlikely(afl->debug)) {

      DEBUGF("calibration stage %d/%d\n", afl->stage_cur + 1, afl->stage_max);

    }

    u64 cksum;

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

    classify_counts(&afl->fsrv);
    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    if (q->exec_cksum != cksum) {

      hnb = has_new_bits(afl, afl->virgin_bits);
      if (hnb > new_bits) { new_bits = hnb; }

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < afl->fsrv.map_size; ++i) {

          if (unlikely(!afl->var_bytes[i]) &&
              unlikely(afl->first_trace[i] != afl->fsrv.trace_bits[i])) {

            afl->var_bytes[i] = 1;
            // ignore the variable edge by setting it to fully discovered
            afl->virgin_bits[i] = 0;

          }

        }

        if (unlikely(!var_detected)) {

          // note: from_queue seems to only be set during initialization
          if (afl->afl_env.afl_no_ui || from_queue) {

            WARNF("instability detected during calibration");

          } else if (afl->debug) {

            DEBUGF("instability detected during calibration\n");

          }

        }

        var_detected = 1;
        afl->stage_max =
            afl->afl_env.afl_cal_fast ? CAL_CYCLES : CAL_CYCLES_LONG;

      } else {

        q->exec_cksum = cksum;
        memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

      }

    }

  }

  if (unlikely(afl->fixed_seed)) {

    diff_us = (u64)(afl->fsrv.exec_tmout - 1) * (u64)afl->stage_max;

  } else {

    stop_us = get_cur_time_us();
    diff_us = stop_us - start_us;
    if (unlikely(!diff_us)) { ++diff_us; }

  }

  afl->total_cal_us += diff_us;
  afl->total_cal_cycles += afl->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  if (unlikely(!afl->stage_max)) {

    // Pretty sure this cannot happen, yet scan-build complains.
    FATAL("BUG: stage_max should not be 0 here! Please report this condition.");

  }

  q->exec_us = diff_us / afl->stage_max;
  q->bitmap_size = count_bytes(afl, afl->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  update_bitmap_score(afl, q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!afl->non_instrumented_mode && first_run && !fault && !new_bits) {

    fault = FSRV_RUN_NOBITS;

  }

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++afl->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    afl->var_byte_count = count_bytes(afl, afl->var_bytes);

    if (!q->var_behavior) {

      mark_as_variable(afl, q);
      ++afl->queued_variable;

    }

  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) { show_stats(afl); }

  return fault;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(afl_state_t *afl) {

  DIR           *sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0, synced = 0, entries = 0;
  u8             path[PATH_MAX + 1 + NAME_MAX];

  sd = opendir(afl->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", afl->sync_dir); }

  afl->stage_max = afl->stage_cur = 0;
  afl->cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {

    u8  qd_synced_path[PATH_MAX], qd_path[PATH_MAX];
    u32 min_accept = 0, next_min_accept = 0;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(afl->sync_id, sd_ent->d_name)) {

      continue;

    }

    entries++;

    // secondary nodes only syncs from main, the main node syncs from everyone
    if (likely(afl->is_secondary_node)) {

      sprintf(qd_path, "%s/%s/is_main_node", afl->sync_dir, sd_ent->d_name);
      int res = access(qd_path, F_OK);
      if (unlikely(afl->is_main_node)) {  // an elected temporary main node

        if (likely(res == 0)) {  // there is another main node? downgrade.

          afl->is_main_node = 0;
          sprintf(qd_path, "%s/is_main_node", afl->out_dir);
          unlink(qd_path);

        }

      } else {

        if (likely(res != 0)) { continue; }

      }

    }

    synced++;

    /* document the attempt to sync to this instance */

    sprintf(qd_synced_path, "%s/.synced/%s.last", afl->out_dir, sd_ent->d_name);
    id_fd =
        open(qd_synced_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (id_fd >= 0) close(id_fd);

    /* Skip anything that doesn't have a queue/ subdirectory. */

    sprintf(qd_path, "%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    struct dirent **namelist = NULL;
    int             m = 0, n, o;

    n = scandir(qd_path, &namelist, NULL, alphasort);

    if (n < 1) {

      if (namelist) free(namelist);
      continue;

    }

    /* Retrieve the ID of the last seen test case. */

    sprintf(qd_synced_path, "%s/.synced/%s", afl->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, DEFAULT_PERMISSION);

    if (id_fd < 0) { PFATAL("Unable to create '%s'", qd_synced_path); }

    if (read(id_fd, &min_accept, sizeof(u32)) == sizeof(u32)) {

      next_min_accept = min_accept;
      lseek(id_fd, 0, SEEK_SET);

    }

    /* Show stats */

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "sync %u", ++sync_cnt);

    afl->stage_name = afl->stage_name_buf;
    afl->stage_cur = 0;
    afl->stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have
       looked at it before; exec a test case if not. */

    u8 entry[12];
    sprintf(entry, "id:%06u", next_min_accept);

    while (m < n) {

      if (strncmp(namelist[m]->d_name, entry, 9)) {

        m++;

      } else {

        break;

      }

    }

    if (m >= n) { goto close_sync; }  // nothing new

    for (o = m; o < n; o++) {

      s32         fd;
      struct stat st;

      snprintf(path, sizeof(path), "%s/%s", qd_path, namelist[o]->d_name);
      afl->syncing_case = next_min_accept;
      next_min_accept++;

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) { continue; }

      if (fstat(fd, &st)) { WARNF("fstat() failed"); }

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) { PFATAL("Unable to mmap '%s'", path); }

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        (void)write_to_testcase(afl, (void **)&mem, st.st_size, 1);

        fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

        if (afl->stop_soon) { goto close_sync; }

        afl->syncing_party = sd_ent->d_name;
        afl->queued_imported +=
            save_if_interesting(afl, mem, st.st_size, fault);
        afl->syncing_party = 0;

        munmap(mem, st.st_size);

      }

      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

  close_sync:
    close(id_fd);
    if (n > 0)
      for (m = 0; m < n; m++)
        free(namelist[m]);
    free(namelist);

  }

  closedir(sd);

  // If we are a secondary and no main was found to sync then become the main
  if (unlikely(synced == 0) && likely(entries) &&
      likely(afl->is_secondary_node)) {

    // there is a small race condition here that another secondary runs at the
    // same time. If so, the first temporary main node running again will demote
    // themselves so this is not an issue

    //    u8 path2[PATH_MAX];
    afl->is_main_node = 1;
    sprintf(path, "%s/is_main_node", afl->out_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) { close(fd); }

  }

  if (afl->foreign_sync_cnt) read_foreign_testcases(afl, 0);

  afl->last_sync_time = get_cur_time();
  afl->last_sync_cycle = afl->queue_cycle;

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  u32 orig_len = q->len;

  /* Custom mutator trimmer */
  if (afl->custom_mutators_count) {

    u8   trimmed_case = 0;
    bool custom_trimmed = false;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_trim) {

        trimmed_case = trim_case_custom(afl, q, in_buf, el);
        custom_trimmed = true;

      }

    });

    if (orig_len != q->len || custom_trimmed) {

      queue_testcase_retake(afl, q, orig_len);

    }

    if (custom_trimmed) return trimmed_case;

  }

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (q->len < 5) { return 0; }

  afl->stage_name = afl->stage_name_buf;
  afl->bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_pow2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, (u32)TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, (u32)TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(afl->stage_name_buf, "trim %s/%s",
            u_stringify_int(val_bufs[0], remove_len),
            u_stringify_int(val_bufs[1], remove_len));

    afl->stage_cur = 0;
    afl->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u64 cksum;

      write_with_gap(afl, in_buf, q->len, remove_pos, trim_avail);

      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

      if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

      /* Note that we don't keep track of crashes or hangs here; maybe TODO?
       */

      ++afl->trim_execs;
      classify_counts(&afl->fsrv);
      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_pow2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(afl->clean_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

        }

      } else {

        remove_pos += remove_len;

      }

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }
      ++afl->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    if (unlikely(afl->no_unlink)) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      u32 written = 0;
      while (written < q->len) {

        ssize_t result = write(fd, in_buf, q->len - written);
        if (result > 0) written += result;

      }

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      ck_write(fd, in_buf, q->len, q->fname);

    }

    close(fd);

    queue_testcase_retake_mem(afl, q, in_buf, q->len, orig_len);

    memcpy(afl->fsrv.trace_bits, afl->clean_trace, afl->fsrv.map_size);
    update_bitmap_score(afl, q);

  }

abort_trimming:

  afl->bytes_trim_out += q->len;
  return fault;

}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

static int fuzz_count = 0;

u8 __attribute__((hot))
common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  if (afl->out_buf_offset > 0) {
    // Rollback out_buf pointer to point to beginning of buffer
    out_buf -= afl->out_buf_offset;
    len += afl->out_buf_offset;
  }

  if (len < 2) {
    // The buffer doesn't have space for script id
    return 0;
  }

  // Set packetdrill script type based on fuzz_count
  u8 script_id = (fuzz_count++ / 1000);
  *(out_buf+1) =  script_id;
  //printf("Inserting to buffer: Fuzz count: %d Script id: %d\n", fuzz_count-1, script_id);

  u8 fault;

  if (unlikely(len = write_to_testcase(afl, (void **)&out_buf, len, 0)) == 0) {

    return 0;

  }

  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_items;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max) {

    show_stats(afl);

  }

  return 0;

}

