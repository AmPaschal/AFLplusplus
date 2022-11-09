#!/usr/bin/env python
# encoding: utf-8
"""
Example Python Module for AFLFuzz

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""

import calendar
import time
import random
import re


def init(seed):
    """
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    """
    #random.seed(seed)


def deinit():
    pass

def get_pd_commands_from_script(filename):

    try:
        with open(filename, "r") as pd_script:
            pd_commands = pd_script.readlines();

            pruned_commands = [command for command in pd_commands if (command.strip() != "" and not command.startswith("//"))];

            return pruned_commands;

    except:
        print("Exception while opening the file");
        return [];

fields = ["src_port", "dst_port", "seq_num", "ack_num", "header_length", "flags", "win_size", "checksum", "urg_pointer"];

fields = ["src_port","ack", "win", "mss"];

def generate_replace_inst(buf, current_counter):

    field_index = buf[current_counter] % len(fields);

    current_counter += 1;

    field = fields[field_index];

    inst = "rep";
    if (field == "src_port"):
        src_port_bytes: bytearray = buf[current_counter: current_counter + 2];
        inst = inst + " tcp src_port 0x" + src_port_bytes.hex().capitalize();
        current_counter += 2;

    elif (field == "ack"):
        src_port_bytes: bytearray = buf[current_counter: current_counter + 4];
        inst = inst + " tcp ack 0x" + src_port_bytes.hex().capitalize();
        current_counter += 2;

    elif (field == "win"):
        src_port_bytes: bytearray = buf[current_counter: current_counter + 2];
        inst = inst + " tcp win 0x" + src_port_bytes.hex().capitalize();
        current_counter += 2;

    elif (field == "mss"):
        src_port_bytes: bytearray = buf[current_counter: current_counter + 2];
        inst = inst + " tcp mss 0x" + src_port_bytes.hex().capitalize();
        current_counter += 2;

    return current_counter, inst;

MAX_INSERT_BYTES = 6;

MAX_DELETE_BYTES = 6;

def generate_insert_inst(buf, current_counter):

    insert_point = buf[current_counter];

    current_counter += 1;

    num_insert_butes = buf[current_counter] % MAX_INSERT_BYTES;

    current_counter += 1;

    insert_bytes: bytearray = buf[current_counter: current_counter + num_insert_butes];

    insert_bytes = insert_bytes.hex().capitalize();

    current_counter += num_insert_butes;

    return current_counter, f"ins tcp {insert_point} 0x{insert_bytes}";


def generate_delete_inst(buf, current_counter):

    delete_point = buf[current_counter];

    current_counter += 1;

    num_truncate_bytes = buf[current_counter] % MAX_INSERT_BYTES;

    current_counter += 1;

    return current_counter, f"trun tcp {delete_point} {num_truncate_bytes}";


def post_process(buf):

#     Called just before the execution to write the test case in the format
#     expected by the target
#
#     @type buf: bytearray
#     @param buf: The buffer containing the test case to be executed
#
#     @rtype: bytearray
#     @return: The buffer containing the test case after

    if (len(buf) < 5):
        return 0;

    current_counter = 0;

    pd_commands = get_pd_commands_from_script("/home/pamusuo/research/ampaschal-packetdrill/gtests/net/tcp/blocking/blocking-accept-fuzz.pkt");
    
    first_byte = buf[current_counter];

    current_counter += 1;

    start_index = first_byte % len(pd_commands);

    updated_commands = pd_commands[0: start_index]

    for i in range(start_index, len(pd_commands)):

        pd_command = pd_commands[i];

        inbound_match = re.search("\+\d*\.?\d* < [S|F|P|\.]", pd_command);

        if (inbound_match is None or (len(buf) - current_counter) < 3):
            updated_commands.append(pd_command);
            continue;

        control_byte = buf[current_counter];

        current_counter += 1;

        control = control_byte % 3;

        if control == 0:
            (current_counter, inst) = generate_replace_inst(buf, current_counter);
        elif control == 1:
            (current_counter, inst) = generate_insert_inst(buf, current_counter);
        else:
            (current_counter, inst) = generate_delete_inst(buf, current_counter);

        if (inst == ""):
            updated_commands.append(pd_command);
        else:
            fuzz_instruction = pd_command.strip() + ' {' + inst + '}\n';
            updated_commands.append(fuzz_instruction);

    updated_command_string = ''.join(updated_commands);

    updated_buf = bytearray(updated_command_string.encode());

    timestamp = calendar.timegm(time.gmtime());

    mutated_filename = f"afl-pd-{timestamp}.pkt"

    with open(mutated_filename, "wb") as mutated_files:
        mutated_files.write(updated_buf);

    pd_command_string = ''.join(pd_commands);

    buf = bytearray(updated_command_string.encode());

    return buf




# Uncomment and implement the following methods if you want to use a custom
# trimming algorithm. See also the documentation for a better API description.

# def init_trim(buf):
#     '''
#     Called per trimming iteration.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be trimmed.
#
#     @rtype: int
#     @return: The maximum number of trimming steps.
#     '''
#     global ...
#
#     # Initialize global variables
#
#     # Figure out how many trimming steps are possible.
#     # If this is not possible for your trimming, you can
#     # return 1 instead and always return 0 in post_trim
#     # until you are done (then you return 1).
#
#     return steps
#
# def trim():
#     '''
#     Called per trimming iteration.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the trimmed data.
#     '''
#     global ...
#
#     # Implement the actual trimming here
#
#     return bytearray(...)
#
# def post_trim(success):
#     '''
#     Called after each trimming operation.
#
#     @type success: bool
#     @param success: Indicates if the last trim operation was successful.
#
#     @rtype: int
#     @return: The next trim index (0 to max number of steps) where max
#              number of steps indicates the trimming is done.
#     '''
#     global ...
#
#     if not success:
#         # Restore last known successful input, determine next index
#     else:
#         # Just determine the next index, based on what was successfully
#         # removed in the last step
#
#     return next_index
#
# def post_process(buf):
#     '''
#     Called just before the execution to write the test case in the format
#     expected by the target
#
#     @type buf: bytearray
#     @param buf: The buffer containing the test case to be executed
#
#     @rtype: bytearray
#     @return: The buffer containing the test case after
#     '''
#     return buf
#
# def havoc_mutation(buf, max_size):
#     '''
#     Perform a single custom mutation on a given input.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be mutated.
#
#     @type max_size: int
#     @param max_size: Maximum size of the mutated output. The mutation must not
#         produce data larger than max_size.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the mutated data
#     '''
#     return mutated_buf
#
# def havoc_mutation_probability():
#     '''
#     Called for each `havoc_mutation`. Return the probability (in percentage)
#     that `havoc_mutation` is called in havoc. Be default it is 6%.
#
#     @rtype: int
#     @return: The probability (0-100)
#     '''
#     return prob
#
# def queue_get(filename):
#     '''
#     Called at the beginning of each fuzz iteration to determine whether the
#     test case should be fuzzed
#
#     @type filename: str
#     @param filename: File name of the test case in the current queue entry
#
#     @rtype: bool
#     @return: Return True if the custom mutator decides to fuzz the test case,
#         and False otherwise
#     '''
#     return True
#
# def queue_new_entry(filename_new_queue, filename_orig_queue):
#     '''
#     Called after adding a new test case to the queue
#
#     @type filename_new_queue: str
#     @param filename_new_queue: File name of the new queue entry
#
#     @type filename_orig_queue: str
#     @param filename_orig_queue: File name of the original queue entry
#     '''
#     pass
