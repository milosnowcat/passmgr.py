# TODO hacer un programa en terminal para guardar claves,
# usara una clave maestra para encriptar las claves,
# copiara la clave al portapaeles para no mostrarla en la terminal,
# podra generar claves aleatorias

import utils
import os

def createPassword(secret):
    while 1:
        print("\nCreate password options:")
        print("(1) add password")
        print("(2) generate random password")
        print("(99) return\n")

        option = input(":")

        if option == '1':
            utils.addPassword(secret)
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
        elif option == 'q':
            break

main()
