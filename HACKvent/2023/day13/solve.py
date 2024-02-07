import base64

zipname = 'firmware.zip'
oldfile = open(zipname, 'rb').read()
print(base64.b64encode(oldfile))