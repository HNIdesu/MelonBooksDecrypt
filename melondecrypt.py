import json
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CBC
from Crypto.Util.Padding import  unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from io import BytesIO
from urllib.request import urlopen,Request
from urllib.parse import urlencode
from argparse import ArgumentParser

import sys
import ssl
import os
import pathlib
import os.path as Path 

parser=ArgumentParser()
parser.add_argument("filepath",help="the path of the melon file")
parser.add_argument("-e","--email",required=True,help="login email adress")
parser.add_argument("-p","--password",required=True,help="login password")
parser.add_argument("-o","--output",required=False,help="output directroy")
args=parser.parse_args(sys.argv[1:])

filepath=args.filepath
email=args.email
password=args.password

if args.output:
    output_directory=args.output
else:
    output_directory="output"
if not Path.exists(output_directory):
    os.makedirs(output_directory,exist_ok=True)
content_id=None
data_chunk=None
encrypt_key=None
filetype=None
with open(filepath,"rb") as br:
    filesize=br.seek(0,2)
    br.seek(0,0)
    if not br.read(4)==b'RIFF':
        quit()
    br.seek(8,0)
    if not br.read(4)==b'BeBG':
        quit()
    br.seek(12,0)
    while br.tell()!=filesize:
        chunk_header=br.read(4).decode("utf-8")
        chunk_size=int.from_bytes(br.read(4),byteorder="little")
        chunk_data=br.read(chunk_size)
        if(chunk_size%2!=0):
            br.seek(1,1)
        if chunk_header=="META":
            xml=ET.fromstring(chunk_data.decode("utf-8"))
            content_id=xml.find("content_id").text
            filetype=xml.find("file_type").text
        elif chunk_header=="KEY ":
            xml=ET.fromstring(chunk_data.decode("utf-8"))
            key_text=xml.find("key").text
            iv=bytes.fromhex(key_text[0:32])
            encrypt_key=bytes.fromhex(key_text[32:])
        elif chunk_header=="data":
            data_chunk=chunk_data
if encrypt_key==None:
    print("key not found")
    quit()

with open('private.key', 'rb') as key_file:
    private_key = RSA.importKey(key_file.read())
context = ssl.create_default_context()
context.set_ciphers("DEFAULT:@SECLEVEL=1")
response=json.loads(urlopen(Request("https://api.melonbooks.co.jp/app/auth.php",data=urlencode({
    "mailaddress":email,
    "password":password,
    "device":"",
    "content_id":content_id,
    "access_key":"S4vQVkERvGkxpKZA",
    "platform":"windows"
}).encode("utf-8"),headers={
    "Content-Type":"application/x-www-form-urlencoded",
    "User-Agent":"Mozilla/5.0",
    "Accept-Language":"en,*"
}),context=context).read().decode("utf-8"))
if not response["melonbooks"]["status"]["code"]==200:
    print("request drm_key fail")
    print(response)
    quit()
encrypted_drm_key=bytes.fromhex(json.loads(response["melonbooks"]["result"]["orders"][0]["drm_key"])["data"]["key"])
drm_key=PKCS1_v1_5.new(private_key).decrypt(encrypted_drm_key,sentinel=None)
aes=AES.new(drm_key,MODE_CBC,iv=iv)
key=unpad(aes.decrypt(encrypt_key),AES.block_size)   

dest_filepath=Path.join(output_directory,pathlib.Path(filepath).with_suffix(f".{filetype}").name)
with BytesIO(data_chunk) as br:
    chunk_length=len(data_chunk)
    with open(dest_filepath,"wb") as bw:
        iv=br.read(16)
        encrypted_data=br.read()
        data=AES.new(key,MODE_CBC,iv).decrypt(encrypted_data)
        bw.write(data)
print(f"the decrypted file has been saved to {dest_filepath}")