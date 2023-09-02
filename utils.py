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

def getData():
    sitename = input("Site Name: ")
    siteurl = input("Site URL: ")
    email = input("Email: ")
    username = input("Username: ")

    return [sitename, siteurl, email, username]

def getPassword(message):
    while 1:
        password = getpass(message)

        if password == getpass("Re-type: ") and password != "":
            break

        rich.print("[yellow][-] Please try again.[/yellow]")
    
    return password

def createSecret():
    rich.print("[green][+] Creating new config [/green]")

    password = getPassword("Choose a MASTER PASSWORD: ")

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

def encryptPassword(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce + ciphertext + tag

def addPassword(secret, data, password):
    mk = computeMasterKey(secret)
    encrypted = encryptPassword(mk, password)

    db = dbconfig()
    cursor = db.cursor()
    sql = "INSERT INTO entries (sitename, siteurl, email, username, password) values (?, ?, ?, ?, ?)"
    val = (data[0], data[1], data[2], data[3], encrypted)
    cursor.execute(sql, val)
    db.commit()

    rich.print("[green][+][/green] Added entry ")

def newPassword(length=12):
    rich.print("[red][+][/red] Specify length of the password to generate (default 12) ")
    nlength = input()

    if nlength != length and nlength.isdigit():
        length = int(nlength)

    newpass = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(length)])

    pyperclip.copy(newpass)
    rich.print("[green][+][/green] Password generated and copied to clipboard")

    return newpass
