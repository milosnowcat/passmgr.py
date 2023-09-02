import sqlite3
import rich
from getpass import getpass
import hashlib
from Crypto.Random import get_random_bytes
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

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

def createSecret():
    rich.print("[green][+] Creating new config [/green]")

    while 1:
        password = getpass("Choose a MASTER PASSWORD: ")

        if password == getpass("Re-type: ") and password != "":
            break

        rich.print("[yellow][-] Please try again.[/yellow]")

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
            exit()

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

def addPassword(secret):
    sitename = input("Site Name: ")
    siteurl = input("Site URL: ")
    email = input("Email: ")
    username = input("Username: ")

    while 1:
        site_password = getpass()

        if site_password == getpass("Re-type: ") and site_password != "":
            break

        rich.print("[yellow][-] Please try again.[/yellow]")

    mk = computeMasterKey(secret)
    site_encrypted = encryptPassword(mk, site_password)

    db = dbconfig()
    cursor = db.cursor()
    sql = "INSERT INTO entries (sitename, siteurl, email, username, password) values (?, ?, ?, ?, ?)"
    val = (sitename, siteurl, email, username, site_encrypted)
    cursor.execute(sql, val)
    db.commit()

    rich.print("[green][+][/green] Added entry ")
