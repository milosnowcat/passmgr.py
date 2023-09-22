#                      .                    .                           
#                 :-:--=:-:::.             :=-**##*=:                   
#                  :=----------.         .-%@@@@@@@@@%:                 
#                 :-------------:        :@@@@@@@@@@@@%.                
#                :-=-----------==:       +@@@@@@@@@@@@@#                
#              .------------=------.     =@@@@@@@@@@@@@#                
#               :=-=-------===-=--      .+%@@@@@@@@@@@#=                
#                --=--------==-=-.       -*%@@@@@@@@@*-.                
#                   ::----===+-             .#%@@@@*.                   
#                      -+++=: .               :+##+                     
#                     -+=====.              .=%@@%%%#=                  
#                  :-----------:.        :+#%%%@@@@@%@%+-               
#                -----------------      -%%%%%@@@%@@%%@%%*              
#               .-==----------==--:     #%%%@%@@@@@@@@@@%%.             
#               :-=+----------*=---    =%%%@@%%@@@%%@@@%%%=             
#               ---=----------*----:  .#%%%@@%%@@@%@%@@%%%%             
#              :-===----------+=---=  -#%%%@@%%@%@%@%@@%%%%=            
#                --=----------=#==+.   ==+%@@%%@@@%@%@@*++.             
#                --=-----------*=---  :===#@@%%@@@%@%%%--=              
#                -==-----------++--=  ---:#@%@@@%%%@@@%--=              
#                -=------------=:--=. =-- %@%%%%%%@%%%@=-=              
#               .-+-------------.:---.--: %%%%%%%%@%%@@+==              
#               :-++*++++++*+***. --=+--  *###########**-=              
#               --*+++++++++*+++: :--*-: :------=------*-=              
#               =-*++++++++*+***- .--*-. :-------------+-=              
#              .--*+++=+*++*+***+ :==*=: -------=------===:             
#              :=+++++==+++*++**+ -*++=. -------+-------+=:             
#               -++++=+==**+++***  :-:   -------+-------+.              
#                -+++=++=****+**#        -------+=------=               
#                .++==*=---=*+**+        =------+*------=               
#                 ----=    :---=          ====-.::+====                 
#            :**#==---=:   ----= ..   .:::=--=+*%#*--=+***. .--:..      
#            .=+**#=--==   :=--=%@*:.-=+%%*--=: ::+=--+***+=#@%*-=-::.  
#                :+=--=. :::=--=:.-*#%*--=*---+-+**=--=--=+**+*=**%@%=  
#                  =--= .#%%=--=.  +*#%#= +---#%++#=---.+%@%+  .+++*+-  
#                  ====   .:+===:   -==+= :===*+: -==== .--:.      ..   
#                  =--=     ----:         .----   :=---                 
#                  ----     :---:         .=---   .=---                 
#                  ----     :---:         .=---    =---                 
#                  ---:     :---:         .=---    +---                 
#                  +##%.    =*##-         -%%#:    %%%#                 
#                 :@@@@-    #@@@+         %@@@*   :@@@%:                
#                 .====.    -++=:         =+==-    --==.                

# @milosnowcat

import utils

def createPassword(secret):
    """
    The function `createPassword` allows the user to add or generate a password and store it in a secret
    variable.
    
    :param secret: The parameter "secret" is not defined in the given code snippet. It seems like it is
    intended to be a variable or value that is passed into the function createPassword(). Without
    knowing the specific purpose or context of the code, it is difficult to determine what the "secret"
    parameter should be
    """
    while 1:
        print("\nCreate password options:")
        print("(1) add password")
        print("(2) generate random password")
        print("(99) return\n")

        option = input(":")

        if option == '1':
            utils.addPassword(secret, utils.askData(), utils.askPassword("Password: "))
            break
        elif option == '2':
            utils.addPassword(secret, utils.askData(), utils.newPassword())
            break
        elif option == '99':
            break

def readPassword(secret):
    """
    The function `readPassword` allows the user to choose between different options for reading
    passwords, such as showing all passwords or searching for a specific password.
    
    :param secret: The parameter "secret" is likely a variable or value that represents the secret or
    master password needed to access the passwords. It is used as an argument when calling the
    "getPassword" function from the "utils" module
    """
    while 1:
        print("\nRead password options:")
        print("(1) show all passwords")
        print("(2) search password")
        print("(99) return\n")

        option = input(":")

        if option == '1':
            utils.getPassword(secret, [])
            break
        elif option == '2':
            utils.getPassword(secret, utils.askData())
            break
        elif option == '99':
            break

def updatePassword(secret):
    """
    The function `updatePassword` allows the user to update their password by providing options to show
    all passwords, search for a specific password, or return to the previous menu.
    
    :param secret: The parameter "secret" is not defined in the given code snippet. It seems like it is
    expected to be a secret password or key that is required to access or update the passwords
    """
    while 1:
        print("\nUpdate password options:")
        print("(1) show all passwords")
        print("(2) search password")
        print("(99) return\n")

        option = input(":")

        if option == '1':
            utils.editPassword(secret, [])
            break
        elif option == '2':
            utils.editPassword(secret, utils.askData())
            break
        elif option == '99':
            break

def deletePassword(secret):
    """
    The function `deletePassword` provides options to delete passwords, either by showing all passwords
    or searching for a specific password.
    
    :param secret: The parameter "secret" is the password that is required to access and delete
    passwords
    """
    while 1:
        print("\nDelete password options:")
        print("(1) show all passwords")
        print("(2) search password")
        print("(99) return\n")

        option = input(":")

        if option == '1':
            utils.removePassword(secret, [])
            break
        elif option == '2':
            utils.removePassword(secret, utils.askData())
            break
        elif option == '99':
            break

def main():
    """
    The main function provides a menu-driven interface for creating, reading, updating, and deleting
    passwords using a secret key.
    """
    db = utils.dbconfig()
    secret = utils.checkMaster()

    while 1:
        print("\nChoose an option:")
        print("(c)reate password")
        print("(r)ead password")
        print("(u)pdate password")
        print("(d)elete password")
        print("(q)uit\n")

        option = input(":")

        if option == 'c':
            createPassword(secret)
        elif option == 'r':
            readPassword(secret)
        elif option == 'u':
            updatePassword(secret)
        elif option == 'd':
            deletePassword(secret)
        elif option == 'q':
            break

main()
