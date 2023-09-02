import sqlite3
import rich
from getpass import getpass
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import random
import string
import pyperclip
from rich.console import Console
from rich.table import Table

def encryptPassword(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce + ciphertext + tag

def decryptPassword(key, ciphertext):
    nonce = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except ValueError:
        return None

def dbconfig():
    db = sqlite3.connect("db.sqlite3")

    cursor = db.cursor()
    sql = "SELECT * FROM secrets"

    try:
        cursor.execute(sql)
    except Exception as e:
        rich.print("[red][!][/red] Database is not created ")
        sql = "CREATE TABLE secrets (master_password TEXT NOT NULL, secret_key TEXT NOT NULL)"
        cursor.execute(sql)
        sql = "CREATE TABLE entries (sitename TEXT NOT NULL, siteurl TEXT NOT NULL, email TEXT, username TEXT, password TEXT NOT NULL)"
        cursor.execute(sql)
        rich.print("[green][+][/green] Database created ")
        createSecret()

    return db

def askData():
    sitename = input("Site Name: ")
    siteurl = input("Site URL: ")
    email = input("Email: ")
    username = input("Username: ")

    return [sitename, siteurl, email, username]

def askPassword(message):
    while 1:
        password = getpass(message)

        if password == getpass("Re-type: ") and password != "":
            break

        rich.print("[yellow][-] Please try again.[/yellow]")
    
    return password

def createSecret():
    rich.print("[green][+] Creating new config [/green]")

    password = askPassword("Choose a MASTER PASSWORD: ")

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    rich.print("[green][+][/green] Generated hash of MASTER PASSWORD")

    key = get_random_bytes(16)
    rich.print("[green][+][/green] Secret Key generated")

    db = dbconfig()
    cursor = db.cursor()
    sql = "INSERT INTO secrets (master_password, secret_key) values (?, ?)"
    val = (password_hash, key)
    cursor.execute(sql, val)
    db.commit()

    rich.print("[green][+][/green] Added to the database")

    rich.print("[green][+] Configuration done![/green]")

def checkMaster():
    while 1:
        password = getpass("MASTER PASSWORD: ")
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        db = dbconfig()
        cursor = db.cursor()
        sql = "SELECT * FROM secrets"
        cursor.execute(sql)
        result = cursor.fetchall()[0]

        if result == None:
            createSecret()
        elif password_hash == result[0]:
            break
        else:
            rich.print("[red][!] WRONG! [/red]")

    db.close()
    return [password, result[1]]

def computeMasterKey(secret):
    password = secret[0].encode()
    salt = secret[1]
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return key

def addPassword(secret, data, password):
    mk = computeMasterKey(secret)
    encrypted = encryptPassword(mk, password)

    if len(queryPasswords(data)) == 0:
        db = dbconfig()
        cursor = db.cursor()
        sql = "INSERT INTO entries (sitename, siteurl, email, username, password) values (?, ?, ?, ?, ?)"
        val = (data[0], data[1], data[2], data[3], encrypted)
        cursor.execute(sql, val)
        db.commit()

        rich.print("[green][+][/green] Added entry ")
    else:
        rich.print("[yellow][-][/yellow] Entry with these details already exists")

def newPassword(length=12):
    rich.print("[red][+][/red] Specify length of the password to generate (default 12) ")
    nlength = input()

    if nlength != length and nlength.isdigit():
        length = int(nlength)

    newpass = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(length)])

    pyperclip.copy(newpass)
    rich.print("[green][+][/green] Password generated and copied to clipboard")

    return newpass

def choosePassword(secret, results):
    while 1:
        select = input("Copy password #")

        if select.isdigit() and (int(select) <= len(results) and int(select) > 0):
            break
        elif select == "0":
            return ""

        rich.print("[yellow][-][/yellow] Selected password is not valid ")
    
    mk = computeMasterKey(secret)
    decrypted = decryptPassword(mk, results[int(select)-1][4])

    return decrypted

def searchPassword(form, query):
    columns = ['sitename', 'siteurl', 'email', 'username']
    j = 0

    for i in range(4):
        if form[i] != "":
            if j != 0:
                query += " AND "
            query += f"{columns[i]} = '{form[i]}'"
            j += 1
    
    return query

def showPasswords(results):
    if len(results) == 0:
        rich.print("[yellow][-][/yellow] No results for the search ")
        return False
    
    table = Table(title="Results")
    table.add_column("#")
    table.add_column("Site Name")
    table.add_column("URL")
    table.add_column("Email")
    table.add_column("Username")
    table.add_column("Password")

    for i in results:
        table.add_row(str(results.index(i)+1), i[0], i[1], i[2], i[3], "{hidden}")

    console = Console()
    console.print(table)

    return True

def queryPasswords(data):
    db = dbconfig()
    cursor = db.cursor()
    sql = ""

    if len(data) == 0:
        sql = "SELECT * FROM entries"
    else:
        sql = searchPassword(data, "SELECT * FROM entries WHERE ")

    cursor.execute(sql)
    results = cursor.fetchall()

    return results

def getPassword(secret, data):
    results = queryPasswords(data)

    if showPasswords(results):
        decrypted = choosePassword(secret, results)
        if decrypted:
            pyperclip.copy(decrypted)
            rich.print("[green][+][/green] Password copied to clipboard")
        else:
            rich.print("[red][!] ERROR WHILE DECYPTION [/red]")

def setNewPassword(secret):
    while 1:
        print("\nSet new password options:")
        print("(a) set password")
        print("(b) set random password")
        print("(z) return\n")

        option = input(":")

        if option == 'a':
            password = askPassword("New password: ")
            break
        elif option == 'b':
            password = newPassword()
            break
        elif option == 'z':
            return None
    
    mk = computeMasterKey(secret)
    encrypted = encryptPassword(mk, password)

    return encrypted

def editPassword(secret, data):
    results = queryPasswords(data)

    if showPasswords(results):
        while 1:
            select = input("Edit password #")

            if select.isdigit() and (int(select) <= len(results) and int(select) > 0):
                break
            elif select == "0":
                return

            rich.print("[yellow][-][/yellow] Selected password is not valid ")

        sel = results[int(select)-1]
        pwd = setNewPassword(secret)

        if pwd:
            db = dbconfig()
            cursor = db.cursor()
            sql = "UPDATE entries SET password = ? WHERE sitename = ? AND siteurl = ? AND email = ? AND username = ?"
            val = (pwd ,sel[0], sel[1], sel[2], sel[3])
            cursor.execute(sql, val)
            db.commit()

            rich.print("[green][+][/green] Edited entry ")

def removePassword(secret, data):
    results = queryPasswords(data)

    if showPasswords(results):
        while 1:
            select = input("Delete password #")

            if select.isdigit() and (int(select) <= len(results) and int(select) > 0):
                break
            elif select == "0":
                return

            rich.print("[yellow][-][/yellow] Selected password is not valid ")

        sel = results[int(select)-1]
        sure = input("Are you sure that you want to delete this passwprd? (y/n)")

        if sure == "y" and secret == checkMaster():
            db = dbconfig()
            cursor = db.cursor()
            sql = "DELETE FROM entries WHERE sitename = ? AND siteurl = ? AND email = ? AND username = ?"
            val = (sel[0], sel[1], sel[2], sel[3])
            cursor.execute(sql, val)
            db.commit()

            rich.print("[red][!] Deleted entry [/red]")
