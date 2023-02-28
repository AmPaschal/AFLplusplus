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
import struct
import re
import sys
import os
import binascii


iter_index = 0
debug = 0

def init(seed):
    """
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    """
    #random.seed(seed)


def deinit():
    pass

def debug_print(msg):
    if debug:
        print(msg)

def get_pd_commands_from_script(filename):
    
    try:
        with open(filename, "r") as pd_script:
            pd_commands = pd_script.readlines();
            
            pruned_commands = [command for command in pd_commands if (command.strip() != "" and not command.startswith("//"))];

            return pruned_commands;

    except:
        debug_print("Exception while opening the file");
        return [];

tcp_fields = [
    {"name": "src_port", "no_bytes": 2},
    {"name": "dst_port", "no_bytes": 2},
    {"name": "seq_num", "no_bytes": 4},
    {"name": "ack_num", "no_bytes": 4},
    {"name": "tcp_hdr_len", "no_bytes": 1},
    {"name": "flags", "no_bytes": 1},
    {"name": "win_size", "no_bytes": 2},
    {"name": "tcp_checksum", "no_bytes": 2},
    {"name": "urg_pointer", "no_bytes": 2}
]

#fields = ["src_port","ack", "win", "mss"];

def generate_replace_tcp_inst(buf, current_counter):

    field_index = buf[current_counter] % len(tcp_fields);

    current_counter += 1;

    field_dict = tcp_fields[field_index];

    if (current_counter + field_dict["no_bytes"] > len(buf)):
        return current_counter - 1, ""

    src_port_bytes: bytearray = buf[current_counter: current_counter + field_dict["no_bytes"]];
    inst = "rep tcp " + field_dict["name"] + " 0x" + src_port_bytes.hex().capitalize();
    current_counter += field_dict["no_bytes"];

    return current_counter, inst;


ip_fields = [
    {"name": "version_ihl", "no_bytes": 1},
    {"name": "dscp_esn", "no_bytes": 1},
    {"name": "tot_len", "no_bytes": 2},
    {"name": "iden", "no_bytes": 2},
    {"name": "flags_fragoff", "no_bytes": 2},
    {"name": "ttl", "no_bytes": 1},
    {"name": "protocol", "no_bytes": 1},
    {"name": "ip_checksum", "no_bytes": 2},
    {"name": "src_ip", "no_bytes": 4},
    {"name": "dest_ip", "no_bytes": 4}
]

def generate_replace_ip_inst(buf, current_counter):

    field_index = buf[current_counter] % len(ip_fields);

    current_counter += 1;

    field_dict = ip_fields[field_index];

    if (current_counter + field_dict["no_bytes"] > len(buf)):
        return current_counter - 1, ""

    rep_bytes: bytearray = buf[current_counter: current_counter + field_dict["no_bytes"]];
    inst = "rep ipv4 " + field_dict["name"] + " 0x" + rep_bytes.hex().capitalize();
    current_counter += field_dict["no_bytes"];

    return current_counter, inst;


MAX_INSERT_BYTES = 4;

MAX_DELETE_BYTES = 6;

MAX_INSERT_POINT = 20;

def generate_insert_random(buf, current_counter):

    insert_point = buf[current_counter] % MAX_INSERT_POINT;

    current_counter += 1;

    num_insert_butes = buf[current_counter] % MAX_INSERT_BYTES;

    current_counter += 1;

    insert_bytes: bytearray = buf[current_counter: current_counter + num_insert_butes];

    if (len(insert_bytes) == 0):
        return current_counter - 2, "";

    insert_bytes = insert_bytes.hex().capitalize();

    current_counter += num_insert_butes;

    return current_counter, f"ins tcp {insert_point} 0x{insert_bytes}";

insert_types = ["tcp_option", "ipv4_option", "random_bytes"]

def generate_insert_inst(buf, current_counter):

    if (len(buf) < current_counter + 7):
        return current_counter, ""

    insert_type_idx = buf[current_counter] % len(insert_types);
    current_counter += 1;

    if (insert_type_idx == 0):
        return generate_insert_tcp_option(buf, current_counter);
    elif (insert_type_idx == 1):
        return generate_insert_IPv4_option(buf, current_counter)
    else:
        return generate_insert_random(buf, current_counter);

NUM_TCP_KINDS = 5
MAX_TCP_LEN = 3

def generate_insert_tcp_option(buf, current_counter):

    option_kind = buf[current_counter] % NUM_TCP_KINDS
    current_counter += 1
    option_len = buf[current_counter] % MAX_TCP_LEN
    current_counter += 1
    option_values = buf[current_counter: current_counter + option_len]
    current_counter += option_len

    #debug_print(f"option_kind: {option_kind} \n option_len: {option_len} \n option_values: {option_values}")

    option_kind_hex = "{:02x}".format(option_kind)
    option_len_hex = "{:02x}".format(option_len) 
    option_values_hex = option_values.hex()

    return current_counter, f"ins tcp 20 0x{option_kind_hex}{option_len_hex}{option_values_hex}"

NUM_IP_KINDS = 5
MAX_IP_OPTION_LEN = 3

def generate_insert_IPv4_option(buf, current_counter):

    option_kind = buf[current_counter] % NUM_IP_KINDS
    current_counter += 1
    option_len = buf[current_counter] % MAX_IP_OPTION_LEN
    current_counter += 1
    option_values = buf[current_counter: current_counter + option_len]
    current_counter += option_len

    option_len_value = option_len + 2

    #debug_print(f"option_kind: {option_kind} \n option_len: {option_len_value} \n option_values: {option_values}")

    option_kind_hex = "{:02x}".format(option_kind)
    option_len_hex = "{:02x}".format(option_len_value) 
    option_values_hex = option_values.hex()

    return current_counter, f"ins ipv4 20 0x{option_kind_hex}{option_len_hex}{option_values_hex}"


def generate_truncate_tcp_header_inst(buf, current_counter):

    return current_counter, f"trun tcp 0 20"


def generate_delete_inst(buf, current_counter):

    delete_point = buf[current_counter];

    current_counter += 1;

    num_truncate_bytes = buf[current_counter] % MAX_INSERT_BYTES;

    current_counter += 1;

    return current_counter, f"trun tcp {delete_point} {num_truncate_bytes}";


tcp_states = [
    ("ESTABLISHED", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-established.pkt", 9),
    ("ESTABLISHED-OPTION", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-established-option.pkt", 9),
    ("LISTEN", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-listen.pkt", 5),
    ("SEND", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-send.pkt", 11),
    ("SYN_RECEIVED", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-syn-rcvd.pkt", 8),
    ("SYN_SENT", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-syn-sent.pkt", 4),
    ("LAST_ACK", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-last-ack.pkt", 10),
    ("FIN_WAIT", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/templates/fuzz-template-tcp-fin-wait.pkt", 12)
]

udp_states = [
    ("SOCKET_OPEN", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/udp_templates/fuzz_template_socket_open.pkt", 5),
    ("SOCKET_CLOSED", "/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/udp_templates/fuzz_template_socket_closed.pkt", 1)
]

opcodes = [
(0, "REP_TCP_SEQ_NUM", "rep tcp seq_num", True),
(1, "REP_TCP_ACK_NUM", "rep tcp ack_num", True),
(2, "INS_TCP_OPTION", "ins tcp 20", True),
(3, "REP_TCP_FLAGS", "rep tcp flags", True),
(4, "REP_TCP_WIN_SIZE", "rep tcp win_size", True),
(5, "REP_TCP_SRC_PORT", "rep tcp src_port", True),
(6, "REP_TCP_DEST_PORT", "rep tcp dest_port", True),
(7, "REP_TCP_HEADER_LENGTH", "rep tcp tcp_hdr_len", True),
(8, "REP_IPV4_VERSION_IHL", "rep ipv4 version_ihl", True),
(9, "REP_IPV4_DSCP_ECN", "rep ipv4 dscp_esn", True),
(10, "REP_IPV4_TOT_LEN", "rep ipv4 tot_len", True),
(11, "REP_IPV4_SOURCE_ADDR", "rep ipv4 src_ip", True),
(12, "REP_IPV4_DEST_ADDR", "rep ipv4 dest_ip", True),
(13, "INS_IP_OPTION", "ins ipv4 20", True),
(14, "TRUN_TCP_HEADER", "trun tcp 0", True)
]

def decode_instruction(bytes_: bytes):
    opcode = struct.unpack("!B", bytes_[:1])[0] % len(opcodes)
    debug_print(f"opcode {opcode}")
    opcode_found = False
    for i, op in enumerate(opcodes):
        if op[0] == opcode:
            opcode_found = True
            break
    
    if opcode_found == False:
        return ""
    
    fuzz_inst = ""
    if op[3] == True:
        value = bytes_[4:].hex().upper()
        if len(value) == 0:
            debug_print(f"invalid value: {bytes_.hex().upper()}")
            return "" 
        fuzz_inst = "{" + op[2] + " " + "0x"+value + "}"
    else:
        value_bytes = bytes_[4:].rjust(4, b'\x00')
        value = int.from_bytes(value_bytes, byteorder='big')
        fuzz_inst = "{" + op[2] + " " + str(value) + "}"
    
    return fuzz_inst


def post_process(buf):

#     Called just before the execution to write the test case in the format
#     expected by the target
#
#     @type buf: bytearray
#     @param buf: The buffer containing the test case to be executed
#
#     @rtype: bytearray
#     @return: The buffer containing the test case after

    global iter_index

    if (len(buf) < 4):
        return bytes("", "utf-8");

    # debug_print(f"Fuzz iteration {iter_index}")
    
    state_idx_to_fuzz = buf[1] % len(tcp_states)

    state_to_fuzz = tcp_states[state_idx_to_fuzz]
    iter_index = iter_index + 1

    pd_commands = get_pd_commands_from_script(state_to_fuzz[1]);

    debug_print(f"STate to fuzz: {state_to_fuzz}")
    # debug_print(f"Length of list: {len(pd_commands)}")

    fuzz_index = state_to_fuzz[2] - 1
    
    pd_command = pd_commands[fuzz_index]

    #updated_commands = pd_commands[:-1]
    updated_commands = pd_commands[0: fuzz_index]

    inbound_match = re.search("\+\d*\.?\d* < [S|F|P|\.]?", pd_command);

    if (inbound_match is None):
        updated_commands.append(pd_command);
        return bytes("", "utf-8")

    try:
        inst = decode_instruction(buf)
    except:
        return bytes("", "utf-8")

    if (inst == ""):
        return bytes("", "utf-8")
    else:
        debug_print(f"Fuzz Instruction: {inst}")
        debug_print(f"Script id: {state_idx_to_fuzz} min_length: {buf[2]} max_length: {buf[3]}")
        fuzz_instruction = pd_command.strip() + inst + '\n';
        updated_commands.append(fuzz_instruction);

    if (fuzz_index < len(pd_commands) - 1):
        updated_commands.extend(pd_commands[fuzz_index + 1 :])

    updated_command_string = ''.join(updated_commands);

    updated_buf = bytearray(updated_command_string.encode());

    # timestamp = calendar.timegm(time.gmtime());

    # mutated_filename = f"afl-pd-{timestamp}.pkt"

    # with open(mutated_filename, "wb") as mutated_files:
    #     mutated_files.write(updated_buf); 

    # pd_command_string = ''.join(pd_commands);

    return updated_buf;


if __name__ == "__main__":

    # Check if the user has provided two file paths or a base64 string
    if len(sys.argv) == 3:
        # Get the file paths from the command line arguments
        src_path = sys.argv[1]
        dest_folder_path = sys.argv[2]

        # Open the source file for reading
        with open(src_path, "rb") as src_file:
            # Read the contents of the source file
            src_data = src_file.read()

    elif len(sys.argv) == 2:
        # Get the base64 string from the command line argument
        src_base64 = sys.argv[1]

        # Decode the base64 string into a bytearray
        try:
            src_data = binascii.unhexlify(src_base64)
        except:
            print(f"Error: invalid hex string {src_base64}")
            exit(1)

    else:
        # If not, display an error message and exit
        print("Error: please provide either two file paths or a base64 string")
        exit(1)

    processed_data = post_process(src_data)

    if (len(processed_data) == 0):
        print("Post process retuned empty string")
        exit(1)

    if len(sys.argv) == 3:
        file_name = os.path.basename(src_path)
        dest_file_name = os.path.join(dest_folder_path, file_name + ".pd")

        # Open the destination file for writing
        with open(dest_file_name, "w") as dest_file:
            # Write the contents of the source file to the destination file
            dest_file.write(processed_data.decode("utf-8"))

        # Display a success message
        debug_print(f"Successfully written post-processed data to {dest_file_name}")

    elif len(sys.argv) == 2:
        # Encode the processed data as base64 and print to stdout
        print(binascii.hexlify(processed_data).decode("utf-8"))




    """ buf = b"042af4"
    
    current_counter, inst = generate_truncate_tcp_header_inst(buf, 0)

    debug_print(f"current counter: {current_counter}")
    debug_print("instruction: " + inst) """

