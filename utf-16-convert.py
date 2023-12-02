text = "text to be encoded here"

#format and printing code as UTF-16 little endian
utf16_bytes = text.encode('utf-16le')
print(" ".join(format(byte, '02x') for byte in utf16_bytes))
