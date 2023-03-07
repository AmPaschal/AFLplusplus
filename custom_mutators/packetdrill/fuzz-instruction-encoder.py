import struct

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

def translate_instruction(instruction: str):
    opcode, min_length, max_length, value = instruction.strip().split()
    for i, op in enumerate(opcodes):
        if op[1] == opcode:
            print(f"iterating opcode {op[1]}")
            opcode = op[0]
            break
    print(f"Value {value}")
    if (op[3] == True):
        value_bytes = bytes.fromhex(value[2:]) # convert hex string to bytes
    else:
        value = int(value, 10)
        value_bytes = struct.pack('!B', value)

    script_bytes = struct.pack('!B', 0)

    min_value = int(min_length, 10)
    min_value_bytes = struct.pack('!B', min_value)

    max_value = int(max_length, 10)
    max_value_bytes = struct.pack('!B', max_value)
    return struct.pack("!B", opcode) + script_bytes + min_value_bytes + max_value_bytes + value_bytes # concatenate opcode byte and value bytes

def main():
    with open("fuzz_in_vuln_instructions_2.txt", "r") as f:
        instructions = f.readlines()

    for instruction in instructions:
        with open("/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/fuzz_in_vuln/instruction_"+str(instructions.index(instruction))+".bin", "wb") as f:
            bytes_ = translate_instruction(instruction)
            f.write(bytes_)

if __name__ == "__main__":
    main()
