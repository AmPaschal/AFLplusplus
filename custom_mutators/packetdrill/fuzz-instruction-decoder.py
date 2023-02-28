import struct

opcodes = [
    (0, "INSERT_MSS", "ins tcp mss", True), 
    (1, "INSERT_IP_OPTION", "ins ipv4 20", True), 
    (2, "REPLACE_IPV4_HEADER_LENGTH", "rep ipv4 version_ihl", True), 
    (3, "REPLACE_TCP_HEADER_LENGTH", "rep tcp tcp_hdr_len", True),
    (4, "TRUN_TCP_HEADER", "trun tcp 0", False)
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
    with open("/home/pamusuo/research/rtos-fuzzing/FreeRTOS/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Posix/out/default/crashes/id:000000,sig:11,src:000029,time:2034927,execs:2114,op:havoc,rep:4", "rb") as f:
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
