# Library for csv file io
import csv
# Library for time
import time
# Library for hashBackend (openssl)
# https://cryptography.io/en/latest/hazmat/backends/
from cryptography.hazmat.backends import openssl
# Lirary for Hash functions like SHA-2 family, SHA-3 family, Blake2, and MD5
# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
from cryptography.hazmat.primitives import hashes
# Node object for building a binary search tree
# Source: https://www.tutorialspoint.com/python/python_binary_tree.htm
class Node:
    # Constructor
    def __init__(self, password, username):
        self.left = None
        self.right = None
        self.password = password
        self.username = username
    # Inserts node into the tree
    def insert(self, password, username):
        if self.password:
            if password < self.password:
                if self.left is None:
                    self.left = Node(password, username)
                else:
                    self.left.insert(password, username)
            elif password > self.password:
                if self.right is None:
                    self.right = Node(password, username)
                else:
                    self.right.insert(password, username)
            elif password == self.password:
                self.username = self.username + ", " + username
        else:
            self.password = password
            self.username = username
# Prints out the account tree and indents each node by depth for readability
def print_tree(node, depth):
    if node is None:
        return
    print(("  " * depth) + node.username + " : " + node.password)
    print_tree(node.left, depth + 1)
    print_tree(node.right, depth + 1)
# Builds a tree from a 2D List where the first element is username and second element is the password
def build_tree(data):
    root = Node(data[0][1], data[0][0])
    for i in range(1, len(data)):
        root.insert(data[i][1], data[i][0])
    return root
# Returns the lowest value of the sub tree
def min_value_node(node):
    current = node
    while current.left is not None:
        current = current.left
    return current
# Removes a node from a tree with a given value
def delete_node_with_value(root, password):
    if root is None:
        return root
    if password < root.password:
        root.left = delete_node_with_value(root.left, password)
    elif password > root.password:
        root.right = delete_node_with_value(root.right, password)
    else:
        if root.left is None:
            temp = root.right
            root = None
            return temp
        elif root.right is None:
            temp = root.left
            root = None
            return temp
        temp = min_value_node(root.right)
        root.password = temp.password
        root.username = temp.username
        root.right = delete_node_with_value(root.right, temp.password)
    return root
# Returns an account node that has the given test_password
def get_account(node, test_password):
    if node is None or test_password == node.password:
        return node
    if test_password < node.password:
        return get_account(node.left, test_password)
    else:
        return get_account(node.right, test_password)
# Unsalted password cracking function
# tests each account with each possible string with lengths <= max length
# when an account is cracked the username and unhashed password is written to the console and the given outfile
def crack_passwords(root, test_password, length_remaining, outfile):
    if length_remaining == 0:
        return
    for i in range(26):
        new_test_password = test_password + chr(97 + i)
        # hash the new_test_password
        digest = hashes.Hash(hashes.SHA256(), backend=openssl.backend)
        digest.update(new_test_password.encode("ascii"))
        hashed_test_string = digest.finalize().hex()
        # find an account with the given password
        cracked_account = get_account(root, hashed_test_string)
        # if we found an account that uses the test_password
        if cracked_account is not None:
            # delete the cracked account from the tree
            root = delete_node_with_value(root, hashed_test_string)
            # write the data to the console and outfile
            print(cracked_account.username + "," + new_test_password)
            outfile.write(cracked_account.username + "," + new_test_password + "\n")
        # Recursive call with new_test_password and length--
        crack_passwords(root, new_test_password, length_remaining - 1, outfile)
# Functions very similar to crack_passwords()
def crack_salted_passwords(accounts, test_password, length_remaining, outfile):
    if length_remaining == 0:
        return
    for i in range(26):
        new_test_password = test_password + chr(97 + i)
        for account in accounts:
            new_salted_test_password = new_test_password + account[2]
            digest = hashes.Hash(hashes.SHA256(), backend=openssl.backend)
            digest.update(new_salted_test_password.encode("ascii"))
            hashed_test_string = digest.finalize().hex()
            if hashed_test_string == account[1]:
                print(account[0] + "," + new_test_password)
                outfile.write(account[0] + "," + new_test_password + "\n")
                accounts.remove(account)
        crack_salted_passwords(accounts, new_test_password, length_remaining - 1, outfile)    
# Takes a filename and returns a list of lists of the data
def csv_file_to_list_of_lists(file_name):
    csv_file = open(file_name, 'r')
    csv_reader = csv.reader(csv_file, delimiter=",")
    data = []
    for row in csv_reader:
        data.append(row)
    return data
# Main driver function for this program
# when importing this file in other programs, calling this function will run this program
def password_cracker(testing, length):
    if testing:
        # Crack unsalted passwords
        # Load accounts into list of lists
        accounts = csv_file_to_list_of_lists("accounts1.txt")
        # Open the output file
        outfile = open("unsalted_passwords.txt", "w")
        # Load salted accounts into list of lists
        salted_accounts = csv_file_to_list_of_lists("accounts2.txt")
        # Open the output file
        salted_outfile = open("salted_passwords.txt", "w")
        # Open results file
        results = open("test_results.txt", "a")
        # Build the tree
        root = build_tree(accounts)
        # Print the tree
        # print_tree(root, 0)
        # Get maximum password length
        max_length = length
        # Start timer
        start_time = time.time()
        # Crack passwords
        crack_passwords(root, "", max_length, outfile)
        # Print elapsed time
        results.write("Unsalted Passwords of lenght: " + str(max_length) + "\n")
        results.write("Elapsed time:\t" + str(time.time() - start_time) + " seconds\n")
        # Crack salted passwords
        # Start timer
        start_time = time.time()
        # Crack passwords
        crack_salted_passwords(salted_accounts, "", max_length, salted_outfile)
        # Print elapsed time
        results.write("Salted Passwords of length: " + str(max_length) + "\n")
        results.write("Elapsed time:\t" + str(time.time() - start_time) + " seconds\n")
    else:
        valid_option = False
        while not valid_option:
            print("Option 1: Unsalted Hashes")
            print("Option 2: Salted Hashes")
            type_option = int(input("Enter an account type to crack: "))
            if type_option == 1:
                valid_option = True
                # Crack unsalted passwords
                # Load accounts into list of lists
                accounts = csv_file_to_list_of_lists("accounts1.txt")
                # Build the tree
                root = build_tree(accounts)
                # Print the tree
                print_tree(root, 0)
                # Open the output file
                outfile = open("unsalted_passwords.txt", "w")
                # Get maximum password length
                max_length = int(input("Enter max password length: "))
                # Start timer
                start_time = time.time()
                # Crack passwords
                crack_passwords(root, "", max_length, outfile)
                # Print elapsed time
                print("Elapsed time: " + str(time.time() - start_time) + " seconds")
            elif type_option == 2:
                valid_option = True
                # Crack salted passwords
                # Load salted accounts into list of lists
                accounts = csv_file_to_list_of_lists("accounts2.txt")
                # Open the output file
                outfile = open("salted_passwords.txt", "w")
                # Get maximum password length
                max_length = int(input("Enter max password length: "))
                        # Start timer
                start_time = time.time()
                # Crack passwords
                crack_salted_passwords(accounts, "", max_length, outfile)
                # Print elapsed time
                print("Elapsed time: " + str(time.time() - start_time) + " seconds")
            else:
                print("Invalid option")

if __name__ == "__main__":
    password_cracker(False, 5)