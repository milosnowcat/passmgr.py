# passmgr.py
 Password Manager

## Installation of the PassMgr Project

The PassMgr project is a Python-based password manager that allows you to securely store and manage your passwords. To get started with PassMgr, follow the installation steps below.

### Prerequisites

Before installing the project, ensure you have Python installed on your system. You can download Python from [python.org](https://www.python.org/downloads/).

### Installation Steps

**You can download for windows without python [here](https://github.com/milosnowcat/passmgr.py/releases/latest)!**

1. Clone the GitHub repository to your local machine using the following command:

   ```bash
   git clone https://github.com/milosnowcat/passmgr.py.git
   ```

2. Navigate to the project directory:

   ```bash
   cd passmgr.py
   ```

3. Install the required dependencies using pip:

   ```bash
   pip install -r requirements.txt
   ```

That's it! You have successfully cloned the PassMgr project and installed the required dependencies.

---

## Using the PassMgr Project

PassMgr is a password manager application in Python. It allows you to create, read, update, and delete password entries securely. Follow these steps to use the application:

### User Interface

The user interface provides options to create, read, update, and delete password entries. It also requires a master password for secure access.

### Creating a Password

1. To create a new password entry, run the PassMgr application by executing the Python script:

   ```bash
   python main.py
   ```

2. The application will display a menu with options. Select the "Create password" option by entering 'c'.

3. You will be prompted with the following options:
   - (1) Add password manually
   - (2) Generate a random password
   - (99) Return to the previous menu

4. Choose either option '1' to manually add a password or option '2' to generate a random password.

5. If you choose to add a password manually, enter the required details for the password entry, including site name, site URL, email, and username.

6. If you choose to generate a random password, a strong password will be generated and copied to your clipboard.

### Reading Passwords

1. Select the "Read password" option from the main menu by entering 'r'.

2. You will be prompted with the following options:
   - (1) Show all passwords
   - (2) Search for a password
   - (99) Return to the previous menu

3. Choose either option '1' to display all stored passwords or option '2' to search for a specific password entry.

4. If you select option '2', you will be prompted to enter search criteria, such as site name, site URL, email, and username.

5. Password entries matching the search criteria will be displayed.

### Updating Passwords

1. Select the "Update password" option from the main menu by entering 'u'.

2. You will be prompted with the following options:
   - (1) Show all passwords
   - (2) Search for a password
   - (99) Return to the previous menu

3. Choose either option '1' to display all stored passwords or option '2' to search for a specific password entry to update.

4. Follow the prompts to edit and update the selected password entry.

### Deleting Passwords

1. Select the "Delete password" option from the main menu by entering 'd'.

2. You will be prompted with the following options:
   - (1) Show all passwords
   - (2) Search for a password
   - (99) Return to the previous menu

3. Choose either option '1' to display all stored passwords or option '2' to search for a specific password entry to delete.

4. Confirm your choice to delete the selected password entry.

### Exiting the Application

To exit the application, select the "Quit" option from the main menu by entering 'q'.

Enjoy using PassMgr to securely manage your passwords!

---

Please note that PassMgr requires a master password for access. Ensure you remember your master password as it is essential for decrypting and accessing your stored passwords.
