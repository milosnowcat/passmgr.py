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
