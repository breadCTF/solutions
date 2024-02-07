import argparse
from PIL import Image

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('image_path', help='Path to the image file')
    args = parser.parse_args()

    image = Image.open(args.image_path)
    width, height = image.size
    image_data = image.getdata()
    
    cblue =  [[image_data[y * width + x][2] for y in range(height)]  for x in range(width)]
    cred =  [[image_data[y * width + x][0] for y in range(height)] for x in range(width)]
    
    rickroll = ""
    for i, blue in enumerate(cblue):
        rickroll += ''.join(chr(i) for i in [b ^ cred[i][j % len(cred)] for j, b in enumerate(blue)])
    print(rickroll)

if __name__ == "__main__":
    main()
