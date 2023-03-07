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

def decode_instruction(bytes_: bytes):
    opcode = struct.unpack("!B", bytes_[:1])[0] % len(opcodes)
    print(f"opcode {opcode}")
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
        fuzz_inst = "{" + op[2] + " " + "0x"+value + "}"
    else:
        value_bytes = bytes_[4:].rjust(4, b'\x00')
        value = int.from_bytes(value_bytes, byteorder='big')
        fuzz_inst = "{" + op[2] + " " + str(value) + "}"
    
    return fuzz_inst

def main():
    with open("/home/pamusuo/research/rtos-fuzzing/AFLplusplus/custom_mutators/packetdrill/fuzz_in_vuln/instruction_0.bin", "rb") as f:
        bytes_ = f.read()
    print(f"Len bytes: {len(bytes_)}")
    instruction = decode_instruction(bytes_)
    print(f"Fuzz instruction: {instruction}")

    script_id = struct.unpack("!B", bytes_[1:2])[0]
    min_length = struct.unpack("!B", bytes_[2:3])[0]
    max_length = bytes_[3]
    print(f"Script id: {script_id} min_length: {min_length} max_length: {max_length}")

if __name__ == "__main__":
    main()
