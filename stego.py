import sys
import hashlib
from PIL import Image

# TODO: Overwrite timestamps
# TODO: Remove pillow dependence so we can use any non-encrypted/compressed files
# VALIDATED: Remove the rng, we need an algorithm to make it repeatable across systems -- validated

# what's the secret password
def keyStream(passphrase, num_pairs):
    st = []
    counter = 0
    while len(st) < num_pairs:
        seed = hashlib.sha256(passphrase.encode('utf-8') + counter.to_bytes(4, 'big')).digest() # sha256 + counter as nonce
        for b in seed:
            st.extend([(b >> 6) & 0b11, (b >> 4) & 0b11, (b >> 2) & 0b11, b & 0b11]) # turn seed in to four bit-pairs
        counter += 1

    print(st) # quick test -- remove 
    return st[:num_pairs]


# separate message into 2-bit pairs
def messagePairs(message):
    chars = list(message)
    bits = []
    
    for char in chars:
        unicode = ord(char)
        binary = format(unicode, '08b') # get binary
        bits.append(binary)
        
    bit_string = ''.join(bits)
    
    if len(bit_string) % 2 != 0:
        bit_string += '0' # pad the odd if needed
        
    pairs = []
    
    for i in range(0, len(bit_string), 2):
        chunk = bit_string[i:i+2]
        value = int(chunk, 2)   # convert "00","01","10","11" -> 0-3
        pairs.append(value)

    return pairs


# file headers
magic_numbers = {
    'png' : [bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])],
    'jpg' : [bytes([0xFF, 0xD8]), bytes([0xFF, 0xD9])], # need to incorporate later (lossy is pain), and incorporate other file types
}


# identify file type based on start bytes
def getFileType(file):
    with open(file, 'rb') as f:
        data = f.read()
        for type in magic_numbers:
            if data.startswith(magic_numbers[type][0]): # get start
                return type
    return None
   
   
def encode(infile, outfile, message, passphrase):
    img = Image.open(infile)
    pixels = list(img.getdata())
    flat = []
    
    # flatten image data
    for pixel in pixels:
        if isinstance(pixel, tuple):
            for val in pixel:
                flat.append(val)
        else:
            flat.append(pixel)
    
    msg_pairs = messagePairs(message) # get message bit pairs
    msg_length = len(message.encode('utf-8')) # so we can accurately decode
    
    length_bits = f"{msg_length:032b}"
    length_pairs = []
    
    # store length iin first 32 bits in bit pairs
    for i in range(0, 32, 2):
        bit_pair = length_bits[i:i+2]
        pair_value = int(bit_pair, 2)
        length_pairs.append(pair_value)
        
    # build full message stream = length data + message data
    data_pairs = length_pairs + msg_pairs
    
    # fail if image is too small to embed message
    if len(data_pairs) > len(flat):
        raise ValueError(f"Image too small: need {len(data_pairs)} pixels, have {len(flat)}")    

    # gen key stream
    ks = keyStream(passphrase, len(data_pairs))
    
    # lettuce now encode
    for i in range(len(data_pairs)):
        c = data_pairs[i] ^ ks[i] # simple XOR the current stream with keystream
        flat[i] = (flat[i] & 0b11111100) | c # replace the last 2 bits of current pixel with c, keeping the top 6 bits unchanged -- bitwise OR
    
    # repack raw bits and then save
    if isinstance(pixels[0], tuple):
        new_pixels = []
        pixel_length = len(pixels[0])
        for i in range(0, len(flat), pixel_length):
            new_pixel = tuple(flat[i:i+pixel_length])
            new_pixels.append(new_pixel)
    else:
        new_pixels = flat
    
    img.putdata(new_pixels)
    img.save(outfile)

    
def decode(infile, passphrase):
    img = Image.open(infile)
    pixels = list(img.getdata())
    flat = []
    
    # flatten image data
    for pixel in pixels:
        if isinstance(pixel, tuple):
            for val in pixel:
                flat.append(val)
        else:
            flat.append(pixel)
    
    # quick fail if too small
    if len(flat) < 16:
        raise ValueError("Image too small to contain encoded message.")
        
    # decode msg_length
    extracted = []
    for i in range(16): # get msg_length bit pairs (32 bits)
        pair = flat[i] & 0b11 # bitwise AND for last 2
        extracted.append(pair)
        
    ks = keyStream(passphrase, 16) # get keystream for msg_length
    
    # XOR with stream to get msg_length
    length_pairs = []
    for i in range(16):
        length_pairs.append(extracted[i] ^ ks[i])

    # convert bit pairs to 32-bit string
    length_bits = ""
    for pair in length_pairs:
        bit_string = f"{pair:02b}"
        length_bits += bit_string

    msg_len = int(length_bits, 2) # convert to integer
    
    # luttuce now decode msg plz
    num_pairs = msg_len * 4 # 4 pairs per byte
    
    # quick fail for bad key
    if len(flat) < 16 + num_pairs:
        return 'Bad key!'
        
    extracted = []
    for i in range(16, 16 + num_pairs): # get msg bit pairs
        pair = flat[i] & 0b11
        extracted.append(pair)

    # get keystream for msg
    ks = keyStream(passphrase, 16 + num_pairs)[16:]  # skip first 16 pairs (msg_length)
    
    msg_pairs = []
    for i in range(num_pairs):
        msg_pairs.append(extracted[i] ^ ks[i]) # XOR for msg plz
    
    # return to bit string
    bit_string = ""
    for pair in msg_pairs:
        bit_string += f"{pair:02b}"

    # return to char string
    chars = []
    for i in range(0, len(bit_string), 8):
        byte_bits = bit_string[i:i+8]
        chars.append(chr(int(byte_bits, 2)))
        
    return ''.join(chars)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\nUsage:")
        # build args
        print("  Encode: python3 stegopy.py encode <input.png> <output.png> <passphrase> <message>")
        print("  Decode: python3 stegopy.py decode <input.png> <passphrase>\n")
        sys.exit(1)

    mode = sys.argv[1]
        
    if mode == "encode" and len(sys.argv) == 6:
        infile = sys.argv[2]
        
        if getFileType(infile) == 'png': # need to work on a lossy version/other file types
            outfile = sys.argv[3]
            passphrase = sys.argv[4]
            message = sys.argv[5]
            encode(infile, outfile, message, passphrase)
            print(f"\nMessage encoded to: {outfile}\n")
        else:
            print("\nInvalid file type.")
       
    elif mode == "decode" and len(sys.argv) == 4:
        infile = sys.argv[2]
        passphrase = sys.argv[3]
        msg = decode(infile, passphrase)
        print(f"\nDecoded message: {msg}\n")
        
    else:
        print("Invalid arguments")
        