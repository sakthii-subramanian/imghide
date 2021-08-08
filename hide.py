from PIL import Image
from os import path
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from termcolor import cprint
from pyfiglet import figlet_format
from rich import print
from rich.console import Console
from rich.table import Table
import os
import getpass
import sys

# initialise debug variable as a reference to image presence
DEBUG = False

# console object
console = Console()

# header text for transfer
headerText = "M6nMjy5THr2J"


# utility function to encrypt the message to be hidden
def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode() if encode else data

# utility function to decrypt the message to be hidden
def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end;
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

# utility function that converts image to rgb values
def convertToRGB(img):
    try:
        rgba_image = img
        rgba_image.load()
        background = Image.new("RGB", rgba_image.size, (255, 255, 255))
        background.paste(rgba_image, mask=rgba_image.split()[3])
        print("[yellow]Converted image to RGB [/yellow]")
        return background
    except Exception as e:
        print("[red]Couldn't convert image to RGB [/red]- %s" % e)

# function that returns the pixel count
def getPixelCount(img):
    width, height = Image.open(img).size
    return width * height

# function that encodes the mesage in the img
def encodeImage(image, message, filename):
    with console.status("[green]Encoding image..") as status:
        try:
            width, height = image.size
            pix = image.getdata()

            current_pixel = 0
            tmp = 0
            # three_pixels = []
            x = 0
            y = 0
            for ch in message:
                binary_value = format(ord(ch), '08b')

                # For each character, get 3 pixels at a time
                p1 = pix[current_pixel]
                p2 = pix[current_pixel + 1]
                p3 = pix[current_pixel + 2]

                three_pixels = [val for val in p1 + p2 + p3]

                for i in range(0, 8):
                    current_bit = binary_value[i]

                    # 0 - Even
                    # 1 - Odd
                    if current_bit == '0':
                        if three_pixels[i] % 2 != 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1
                    elif current_bit == '1':
                        if three_pixels[i] % 2 == 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1

                current_pixel += 3
                tmp += 1

                # Set 9th value
                if (tmp == len(message)):
                    # Make as 1 (odd) - stop reading
                    if three_pixels[-1] % 2 == 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1
                else:
                    # Make as 0 (even) - continue reading
                    if three_pixels[-1] % 2 != 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1

                if DEBUG:
                    print("Character: ", ch)
                    print("Binary: ", binary_value)
                    print("Three pixels before mod: ", three_pixels)
                    print("Three pixels after mod: ", three_pixels)

                three_pixels = tuple(three_pixels)

                st = 0
                end = 3

                for i in range(0, 3):
                    if DEBUG:
                        print("Putting pixel at ", (x, y), " to ", three_pixels[st:end])

                    image.putpixel((x, y), three_pixels[st:end])
                    st += 3
                    end += 3

                    if (x == width - 1):
                        x = 0
                        y += 1
                    else:
                        x += 1

            encoded_filename = filename.split('.')[0] + "-enc.png"
            image.save(encoded_filename)
            print("\n")
            print("[yellow]Original File: [u]%s[/u][/yellow]" % filename)
            print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]" % encoded_filename)

        except Exception as e:
            print("[red]An error occured - [/red]%s" % e)
            sys.exit(0)


# function that decodes msg from img
def decodeImage(image):
    with console.status("[green]Decoding image..") as status:
        try:
            pix = image.getdata()
            current_pixel = 0
            decoded = ""
            while True:
                # Get 3 pixels each time
                binary_value = ""
                p1 = pix[current_pixel]
                p2 = pix[current_pixel + 1]
                p3 = pix[current_pixel + 2]
                three_pixels = [val for val in p1 + p2 + p3]

                for i in range(0, 8):
                    if three_pixels[i] % 2 == 0:
                        # add 0
                        binary_value += "0"
                    elif three_pixels[i] % 2 != 0:
                        # add 1
                        binary_value += "1"

                # Convert binary value to ascii and add to string
                binary_value.strip()
                ascii_value = int(binary_value, 2)
                decoded += chr(ascii_value)
                current_pixel += 3

                if DEBUG:
                    print("Binary: ", binary_value)
                    print("Ascii: ", ascii_value)
                    print("Character: ", chr(ascii_value))

                if three_pixels[-1] % 2 != 0:
                    # stop reading
                    break

            # print("Decoded: %s"%decoded)
            return decoded
        except Exception as e:
            print("[red]An error occured - [/red]%s" % e)
            sys.exit()


# function that loads img into obj
def test(img):
    image = Image.open(img)
    pix = image.load()
    print(pix[0])
    print(type(pix))

# function to print project credits
def print_credits():
    table = Table(show_header=True)
    table.add_column("Roll-number", style="yellow")
    table.add_column("Name", style="yellow")
    table.add_row("19pw27", "Sakthi S")
    console.print(table)





def main():
    
    while True:
        # Menu Opton
        print("\n[cyan]Choose one: [/cyan]")
        op = int(input("1. Encode\n2. Decode\n3. Exit\n>>"))

        if op == 1:
            # gets the img path
            print("[cyan]Image path (with extension): [/cyan]")
            img = input(">>")
            if (not (path.exists(img))):
                raise Exception("Image not found!")
            
            # gets the msg to be hidden
            print("[cyan]Message to be hidden: [/cyan]")
            message = input(">>")
            message = headerText + message      # attaches header text to the msg
            if ((len(message) + len(headerText)) * 3 > getPixelCount(img)):
                raise Exception("Given message is too long to be encoded in the image.")

            password = ""
            # initialising pwd to the user for authentication
            while 1:
                print("[cyan]Password to encrypt : [/cyan]")
                password = getpass.getpass(">>")
                if password == "":
                    break
                # pwd reconfirmation
                print("[cyan]Re-enter Password: [/cyan]")
                confirm_password = getpass.getpass(">>")

                # pwd matching
                if (password != confirm_password):
                    print("[red]Passwords don't match try again [/red]")
                else:
                    break

            cipher = ""
            if password != "":
                # calling the encryt function
                cipher = encrypt(key=password.encode(), source=message.encode())
                # Add header to cipher
                cipher = headerText + cipher

            else:
                cipher = message

            if DEBUG:
                print("[yellow]Encrypted : [/yellow]", cipher)

            # opening imge
            image = Image.open(img)
            print("[yellow]Image Mode: [/yellow]%s" % image.mode)
            # converting image to rgb mode
            if image.mode != 'RGB':
                image = convertToRGB(image)
            newimg = image.copy()
            # sending image to encodeImage function to hide the encrypted msg
            encodeImage(image=newimg, message=cipher, filename=image.filename)

        elif op == 2:
            # gets the img path
            print("[cyan]Image path (with extension): [/cyan]")

            img = input(">>")
            if (not (path.exists(img))):
                raise Exception("Image not found!")

            # authentication to decrypt the msg
            print("[cyan]Enter password : [/cyan]")
            password = getpass.getpass(">>")

            image = Image.open(img)
            
            # calling decode img to obtain the encrypted msg
            cipher = decodeImage(image)

            header = cipher[:len(headerText)]

            if header.strip() != headerText:
                print("[red]Invalid data![/red]")
                sys.exit(0)

            print()

            if DEBUG:
                print("[yellow]Decoded text: %s[/yellow]" % cipher)

            decrypted = ""
            # calling decrypt function to decrypt the msg found from img
            if password != "":
                cipher = cipher[len(headerText):]
                print("cipher : ", cipher)
                try:
                    decrypted = decrypt(key=password.encode(), source=cipher)
                except Exception as e:
                    print("[red]Wrong password![/red]")
                    sys.exit(0)

            else:
                decrypted = cipher

            header = decrypted.decode()[:len(headerText)]

            # Authentication failed msg
            if header != headerText:
                print("[red]Wrong password![/red]")
                sys.exit(0)

            # printing the decrypted msg
            decrypted = decrypted[len(headerText):]

            print("[green]Decoded Text: \n[bold]%s[/bold][/green]" % decrypted)
        elif op == 3:
            exit()
        else:
            print("Invalid Input")

# main function
if __name__ == "__main__":
    # clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(figlet_format('IMAGE STEGANOGRAPHY', font='starwars'), 'yellow', attrs=['bold'])
    
    # print credits
    print_credits()
    print("\n[bold]This project[/bold] allows you to hide texts inside an image. You can also protect these texts with a password using AES-256.")

    # calling main function
    main()