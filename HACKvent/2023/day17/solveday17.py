from PIL import Image
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

def main():
    # Open encypted file convert to bytes
    ct = bytes_to_long(open('flag.enc', 'rb').read())

    # Open image get p and q
    image = Image.open('0c56b3c2-b017-4c6f-b6a8-a565df124012.png')
    image_bytes = image.tobytes()
    length = len(image_bytes)
    p = bytes_to_long(image_bytes[:length//2])
    q = bytes_to_long(image_bytes[length//2:])
 
    # Do the fun RSA calcs
    n = p * q
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    # Decrypt and write
    pt = pow(ct, d, n)
    open('flag.png', 'wb').write(long_to_bytes(pt))

if __name__ == "__main__":
    main()