from colorama import init, Fore, Back, Style
from termcolor import colored
import sys
import os
init()
user=os.getlogin()
privileges = os.popen('whoami /priv /fo list|findstr "Privilege"').read()
is_admin=os.popen('net localgroup Administrators')
is_admin=list(is_admin)
priv_list=[]
final_list=[]
admin_list=[]
a='''

___________     __                   __________        .__       
\__    ___/___ |  | __ ____   ____   \______   \_______|__|__  __
  |    | /  _ \|  |/ // __ \ /    \   |     ___/\_  __ \  \  \/ /
  |    |(  <_> )    <\  ___/|   |  \  |    |     |  | \/  |\   / 
  |____| \____/|__|_ \\___  >___|  /  |____|     |__|  |__| \_/  
                    \/    \/     \/  

                    By @Stark0de  https://stark0de.github.io


                    '''
print(colored(a, 'green'))


def available_privileges():
    for i in range(30):
        try:
            splitted = privileges.split(': ')[i]
            priv_list.append(splitted)
        except IndexError:
            break
    for i in priv_list:
        final_list.append(i.split('\n')[0])
def quit():
     print(colored("[+] ", 'green'),end='')
     quitting=input("You are an admin, quit the program (Y/N)?: ")
     if quitting == "Y" or quitting == "y":
       sys.exit()
     elif quitting == "N" or quitting == "n":
       pass
     else:
       print(colored("[*] ", 'yellow'),end='')
       print("Bad character, try again")
       quit()

def info():
     print(colored("[*] ", 'yellow'),end='')
     print("Your current user is ", end="")
     print(user)
def check_admin():
     for i in is_admin:
            admin_list.append(i.split('\n')[0])
     if user in admin_list:
        quit()
     else:
        print(colored("[*] ", 'yellow'),end='')
        print("You are not an admin")

def vuln_check():
      if "SeDebugPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeDebugPrivilege found: this user can debug processes, that means it you can just create a new cmd and set the parent process to any with high integrity level using https://github.com/decoder-it/psgetsystem")
      elif "SeRestorePrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeRestorePrivilege found: This user can overwrite any file, using the Windows API along with the FILE_FLAG_BACKUP_SEMANTICS flag, you can perform DLL hijacking of any privileged service. Check out: https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L528")
      elif "SeBackupPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeBackupPrivilege found: This user can perform privileged file operations. Check out: https://decoder.cloud/2018/02/12/the-power-of-backup-operatos/")
      elif "SeTakeOwnershipPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeTakeOwnershipPrivilege found: This user can take ownership of any file. Check out: https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L688")
      elif "SeLoadDriverPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeLoadDriverPrivilege found: This user is able to load and unload drivers: Check out: https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/")
      elif "SeTcbPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeTcbPrivilege found: This user has high trust level. You can check how to exploit it at: https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L418")
      elif "SeCreateTokenPrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeCreateTokenPrivilege found: This user is able to create its own access token via the ZwCreateToken API. Check out: https://decoder.cloud/2019/07/04/creating-windows-access-tokens/")
      elif "SeImpersonatePrivilege" in final_list:
          print(colored("[+] ", 'green'),end='')
          print("SeImpersonatePrivilege found: This is vulnerable to Juicy Potato. Check: https://ohpe.it/juicy-potato/")
      elif "SeAssignPrimaryTokenPrivilege" in final_list:
          print(colored("[+] ", 'yellow'),end='')
          print("SeAssignPrimaryTokenPrivilege found: This is vulnerable to Juicy Potato. Check: https://ohpe.it/juicy-potato/")
      else:
          print(colored("[-] ", 'red'),end='')
          print("No privileged tokens :(")
          print(colored("[-] ", 'red'),end='')
          print("Exitting...")
          sys.exit()


info()
check_admin()
available_privileges()
vuln_check()