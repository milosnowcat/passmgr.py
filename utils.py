import sqlite3
import rich
from getpass import getpass
import hashlib
import random
import string
import pyperclip
from rich.console import Console
from rich.table import Table
from ShieldCipher.encryption.symmetric import encrypt_aes, decrypt_aes, compute_key, get_random_bytes
from tqdm import tqdm

def dbconfig():
    """
    The function `dbconfig()` connects to a SQLite database and checks if the required tables exist,
    creating them if necessary.
    :return: The function `dbconfig()` returns a connection object to the SQLite database.
    """
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
    """
    The function `askData()` prompts the user to enter data for a website, including the site name, URL,
    email, and username, and returns a list containing these values.
    :return: a list containing the values of sitename, siteurl, email, and username.
    """
    sitename = input("Site Name: ")
    siteurl = input("Site URL: ")
    email = input("Email: ")
    username = input("Username: ")

    return [sitename, siteurl, email, username]

def askPassword(message):
    """
    The function `askPassword` prompts the user to enter a password, verifies that it is entered
    correctly by asking the user to re-type it, and returns the password.
    
    :param message: The `message` parameter is a string that represents the prompt or message asking the
    user to enter a password
    :return: the password entered by the user.
    """
    while 1:
        password = getpass(message)

        if password == getpass("Re-type: ") and password != "":
            break

        rich.print("[yellow][-] Please try again.[/yellow]")
    
    return password

def createSecret():
    """
    The function `createSecret()` creates a new configuration by generating a password hash, a secret
    key, and inserting them into a database.
    """
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
    """
    The function `checkMaster()` prompts the user for a master password, hashes it using SHA256, and
    checks if it matches the stored password hash in the database.
    :return: a list containing the password and the second element of the result tuple from the database
    query.
    """
    while 1:
        password = getpass("MASTER PASSWORD: ")
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        db = dbconfig()
        cursor = db.cursor()
        sql = "SELECT * FROM secrets"
        cursor.execute(sql)
        results = cursor.fetchall()
        
        result = []
        for i in enumerate(results):
            if password_hash in i[1]:
                result.append(i[0])

        if not results:
            createSecret()
        elif result:
            break
        else:
            rich.print("[red][!] WRONG! [/red]")

    db.close()
    return [password, results[result[0]][1]]

def addPassword(secret, data, password):
    """
    The function `addPassword` adds an encrypted password entry to a database if an entry with the same
    details does not already exist.
    
    :param secret: The `secret` parameter is a secret value used to compute the master key for
    encryption. It is likely a string or some other form of data that is used as input to the
    `computeMasterKey` function
    :param data: The `data` parameter is a list that contains the following information:
    :param password: The `password` parameter is the password that you want to add to the database
    """
    mk = compute_key(*secret)
    encrypted = encrypt_aes(mk, password)

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
    """
    The function `newPassword` generates a random password of specified length (default 12) and copies
    it to the clipboard.
    
    :param length: The `length` parameter is used to specify the length of the password to generate. By
    default, it is set to 12 characters, defaults to 12 (optional)
    :return: the generated password as a string.
    """
    rich.print("[red][+][/red] Specify length of the password to generate (default 12) ")
    nlength = input()

    if nlength != length and nlength.isdigit():
        length = int(nlength)

    newpass = ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for n in range(length)])

    pyperclip.copy(newpass)
    rich.print("[green][+][/green] Password generated and copied to clipboard")

    return newpass

def choosePassword(secret, results):
    """
    The function `choosePassword` takes a secret and a list of results, prompts the user to select a
    password from the list, and returns the decrypted password corresponding to the selected index.
    
    :param secret: The "secret" parameter is the secret key or passphrase used to generate the master
    key for encryption and decryption
    :param results: The `results` parameter is a list of passwords. Each password is represented as a
    list with 5 elements. The 4th element of each password list is the encrypted password that needs to
    be decrypted
    :return: the decrypted password.
    """
    while 1:
        select = input("Copy password #")

        if select.isdigit() and (int(select) <= len(results) and int(select) > 0):
            break
        elif select == "0":
            return ""

        rich.print("[yellow][-][/yellow] Selected password is not valid ")
    
    mk = compute_key(*secret)
    decrypted = decrypt_aes(mk, results[int(select)-1][4])

    return decrypted

def searchPassword(form, query):
    """
    The function `searchPassword` takes a form and a query as input, and constructs a SQL query based on
    the non-empty fields in the form.
    
    :param form: The `form` parameter is a list that contains the values entered by the user in a form.
    The values in the list correspond to the sitename, siteurl, email, and username fields respectively
    :param query: The `query` parameter is a string that represents the SQL query used to search for
    passwords in a database
    :return: the updated query string.
    """
    columns = ['sitename', 'siteurl', 'email', 'username']
    j = 0

    for i in range(4):
        if form[i] != "":
            if j != 0:
                query += " AND "
            else:
                query += " WHERE "
                
            query += f"{columns[i]} = '{form[i]}'"
            j += 1

    return query

def showPasswords(results):
    """
    The function `showPasswords` displays a table of search results, including site name, URL, email,
    username, and a hidden password.
    
    :param results: The `results` parameter is a list of lists. Each inner list represents a result and
    contains the following information in order:
    :return: The function `showPasswords` returns a boolean value. It returns `True` if there are
    results to display, and `False` if there are no results.
    """
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
    """
    The function `queryPasswords` retrieves password entries from a database based on the provided
    search criteria.
    
    :param data: The `data` parameter is a dictionary that contains the search criteria for querying
    passwords from the database. The keys of the dictionary represent the fields to search for (e.g.,
    "username", "website"), and the values represent the search terms
    :return: the results of the SQL query executed on the database.
    """
    db = dbconfig()
    cursor = db.cursor()
    sql = ""

    if len(data) == 0:
        sql = "SELECT * FROM entries"
    else:
        sql = searchPassword(data, "SELECT * FROM entries")

    cursor.execute(sql)
    results = cursor.fetchall()

    return results

def getPassword(secret, data):
    """
    The function `getPassword` retrieves passwords from a given dataset, displays them, allows the user
    to choose one for decryption using a secret, and then copies the decrypted password to the
    clipboard.
    
    :param secret: The "secret" parameter is the secret key or password used for decryption. It is used
    to decrypt the passwords retrieved from the "data" parameter
    :param data: The `data` parameter is the input data that contains the passwords. It could be a list,
    dictionary, or any other data structure that holds the passwords
    """
    results = queryPasswords(data)

    if showPasswords(results):
        decrypted = choosePassword(secret, results)
        if decrypted:
            pyperclip.copy(decrypted)
            rich.print("[green][+][/green] Password copied to clipboard")
        else:
            rich.print("[red][!] ERROR WHILE DECYPTION [/red]")

def setNewPassword(secret):
    """
    The function `setNewPassword` allows the user to set a new password by either inputting it manually
    or generating a random password.
    
    :param secret: The "secret" parameter is not defined in the code snippet you provided. It seems like
    it should be a value or variable that represents a secret key or passphrase used for encryption
    :return: the encrypted password.
    """
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
    
    mk = compute_key(*secret)
    encrypted = encrypt_aes(mk, password)

    return encrypted

def updatePassword(pwd, sel):
    db = dbconfig()
    cursor = db.cursor()
    sql = "UPDATE entries SET password = ? WHERE sitename = ? AND siteurl = ? AND email = ? AND username = ?"
    val = (pwd ,sel[0], sel[1], sel[2], sel[3])
    cursor.execute(sql, val)
    db.commit()

def updatePasswordData(old_data, new_data):
    db = dbconfig()
    cursor = db.cursor()
    sql = "UPDATE entries SET sitename = ?, siteurl = ?, email = ?, username = ? WHERE sitename = ? AND siteurl = ? AND email = ? AND username = ?"
    val = (new_data[0], new_data[1], new_data[2], new_data[3], old_data[0], old_data[1], old_data[2], old_data[3])
    cursor.execute(sql, val)
    db.commit()

def editPasswordOptions():
    while 1:
        print("\nUpdate password options:")
        print("(1) set new password")
        print("(2) edit password info")
        print("(99) return\n")

        option = input(":")

        if option == '1' or option == '2' or option == '99':
            break

    return option

def editPasswordData(old_data):
    rich.print("[green][+] Current password info: [/green]")
    print(f"Site Name: {old_data[0]}")
    print(f"Site URL: {old_data[1]}")
    print(f"Email: {old_data[2]}")
    print(f"Username: {old_data[3]}")

    rich.print("[yellow][-] Leave blank to mantain same info [/yellow]")
    new_data = askData()

    for i in range(4):
        if new_data[i] == "":
            new_data[i] = old_data[i]

    if len(queryPasswords(new_data)) == 0:
        updatePasswordData(old_data, new_data)
        rich.print("[green][+][/green] Edited entry ")
    else:
        rich.print("[yellow][-][/yellow] Entry with these details already exists")

def editPassword(secret, data):
    """
    The function `editPassword` allows the user to select and edit a password entry in a database.
    
    :param secret: The `secret` parameter is the secret key used for encrypting and decrypting
    passwords. It is used in the `setNewPassword` function to generate a new password and in the
    `editPassword` function to update the password in the database
    :param data: The `data` parameter is the input data that is used to query the passwords. It is
    passed to the `queryPasswords` function to retrieve the results. The exact structure and format of
    the `data` parameter is not provided in the code snippet, so it would depend on how the `query
    :return: the edited entry.
    """
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

        option = editPasswordOptions()

        if option == '1':
            pwd = setNewPassword(secret)

            if pwd:
                updatePassword(pwd, sel)
                rich.print("[green][+][/green] Edited entry ")
        elif option == '2':
            editPasswordData(sel)

def removePassword(secret, data):
    """
    The `removePassword` function allows the user to select and delete a password entry from a database
    if they provide the correct secret and confirm their choice.
    
    :param secret: The `secret` parameter is likely a password or some form of authentication that needs
    to be provided in order to delete a password entry. It is used to check if the provided secret
    matches the master password or authentication mechanism
    :param data: The `data` parameter is the input data that contains the passwords. It is used as an
    argument in the `queryPasswords` function to retrieve the passwords
    :return: nothing.
    """
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
        sure = input("Are you sure that you want to delete this password? (y/n)")

        if sure == "y" and secret == checkMaster():
            db = dbconfig()
            cursor = db.cursor()
            sql = "DELETE FROM entries WHERE sitename = ? AND siteurl = ? AND email = ? AND username = ?"
            val = (sel[0], sel[1], sel[2], sel[3])
            cursor.execute(sql, val)
            db.commit()

            rich.print("[red][!] Deleted entry [/red]")

def deleteMaster(secret):
    password_hash = hashlib.sha256(secret[0].encode()).hexdigest()
    
    db = dbconfig()
    cursor = db.cursor()
    sql = "DELETE FROM secrets WHERE master_password = ? AND secret_key = ?"
    val = (password_hash, secret[1])
    cursor.execute(sql, val)
    db.commit()

    rich.print("[red][!] Deleted old MASTER PASSWORD [/red]")

def changeMaster(secret, new_secret):
    rich.print("[yellow][-] Encrypting your passwords with the new MASTER PASSWORD [/yellow]")
    rich.print("[red][!] Do not close the program [/red]")

    results = queryPasswords([])

    for password in tqdm(results, desc="Processing passwords"):
        mk = compute_key(*secret)
        decrypted = decrypt_aes(mk, password[4])

        new_mk = compute_key(*new_secret)
        encrypted = encrypt_aes(new_mk, decrypted)

        updatePassword(encrypted, password)
    
    deleteMaster(secret)
