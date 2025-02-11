"""This application uses the flask framework to
perform back-end functionality for HTML site."""

import datetime
import logging
import socket
import time
from flask import Flask, render_template, request, redirect, url_for, flash
from passlib.handlers.sha2_crypt import sha256_crypt


def has_upper(passwd):
    """This function tests to see if password has
    any uppercase letters. """
    test_str = str(passwd)
    if any(c.isupper() for c in test_str):
        return True
    return False


def has_lower(passwd):
    """This function tests to see if password has
        any lowercase letters. """
    test_str = str(passwd)
    if any(c.islower() for c in test_str):
        return True
    return False


def has_number(passwd):
    """This function tests to see if password
    has any numbers. """
    test_str = str(passwd)
    if any(c.isnumeric() for c in test_str):
        return True
    return False


def has_special_character(passwd):
    """This function tests to see if password has
    any special characters. """
    if not passwd.isalnum():
        return True
    return False


def valid_password(pss_wd):
    """This function tests to see if password meets
    the proper security requirements. """
    if (len(pss_wd) >= 12 and has_upper(pss_wd) and has_lower(pss_wd)
            and has_number(pss_wd) and has_special_character(pss_wd)):
        return True
    return False


def username(user):
    """This function checks to see if the username
    is in the database file. """
    with open('usernames.txt', encoding="utf-8") as file:
        if user in file.read():
            return True
        return False


def password(passwd):
    """This function checks to see if the password
        is in the database file. """
    with open('passwords.txt', encoding="utf-8") as file:
        if sha256_crypt.verify(passwd, file.read()):
            return True
        return False


def common_passwords(passwd):
    """This method compares the password entered
    with a list of common passwords."""
    line = passwd + '\n'
    with open("CommonPassword.txt", "r", encoding="utf-8") as file:
        list_of_common_passwords = file.readlines()
        if line in list_of_common_passwords or passwd in list_of_common_passwords:
            return True

        return False


def change_password(passwd):
    """This method changes passwords."""
    new_password = sha256_crypt.hash(passwd)
    with open("passwords.txt", encoding="utf-8") as file:
        old = file.read()

    with open('passwords.txt', 'w', encoding="utf-8") as file:
        new = old.replace(old, new_password)
        file.write(new)


hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'  # Secret key


@app.route('/')
def home():
    """This page is the home page which lets the
    user log in or create an account."""
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)

    return render_template("home.html", date=today)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """This page is the sign-up page where the user
    can create an account. """
    if request.method == 'POST':
        user_name = request.form['username']
        pass_word = request.form['password']
        if not user_name:
            flash("Please enter username")
            return redirect(url_for('signup'))

        if not pass_word:
            flash("Please enter password")
            return redirect(url_for('signup'))

        if username(user_name):
            flash("You are already registered. Go back to home page and log in.")
            return redirect(url_for('signup'))

        if common_passwords(pass_word):
            flash("Password is a common one. Please pick another. ")
            return redirect(url_for('signup'))

        if not valid_password(pass_word):
            flash("Make your code more complex: at least 12 characters, at least 1 uppercase,"
                  "at least 1 lowercase, and at least 1 special character")
            return redirect(url_for('signup'))

        with open('usernames.txt', "a", encoding="utf-8") as file1, \
                open('passwords.txt', "a", encoding="utf-8") as file2:
            hash_pass = sha256_crypt.hash(pass_word)
            file1.writelines(user_name)
            file2.writelines(hash_pass)

        return redirect(url_for('guide'))
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)
    return render_template('Register.html', date=today)


@app.route("/login", methods=['POST', 'GET'])
def login():
    """This page is the log-in page."""
    logging.basicConfig(level=logging.WARNING, filename='LogFile.txt',
                        filemode='w', format="%(asctime)s - %(levelname)s - %(message)s")
    if request.method == 'POST':
        user_name = request.form['user']
        pass_word = request.form['pass']
        if username(user_name) and password(pass_word):
            return redirect(url_for('guide'))

        flash("Incorrect username or password.")
        logging.error("Invalid username or password from IP Address: %s", ip_address)
        return redirect(url_for('login'))
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)

    return render_template('signin.html', date=today)


@app.route('/PasswordReset', methods=['POST', 'GET'])
def reset():
    """This page allows the user to reset their password."""
    if request.method == 'POST':
        reset_passwd = request.form["reset"]
        if not reset_passwd:
            flash("Please enter a password")
            return redirect(url_for('reset'))

        if common_passwords(reset_passwd):
            flash("Password is a common one. Please pick another. ")
            return redirect(url_for('reset'))

        if not valid_password(reset_passwd):
            flash("Make your code more complex: at least 12 characters, at least 1 uppercase,"
                  " at least 1 lowercase, and at least 1 special character")
            return redirect(url_for('reset'))

        change_password(reset_passwd)
        return redirect(url_for('login'))

    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)
    return render_template("reset.html", date=today)


@app.route('/BmoreGuide')
def guide():
    """This function renders the HTML page and displays
    the date and time for the 'front page' of the Baltimore guide."""
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)
    return render_template('Bmoreguide.html', date=today)


@app.route('/BmoreGoodPlaces')
def good_and_bad():
    """This function renders the HTML page and displays the date and time
     for the good and bad neighborhoods of Baltimore.
    """
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)

    return render_template('BmoreGoodPlaces.html', date=today)


@app.route('/BmoreGoodFood')
def good_food():
    """This function displays renders and displays the date and time
    for the good food page of my Baltimore guide website. """
    my_time = time.localtime()
    current_time = time.strftime("%H:%M:%S", my_time)
    #  Convert the date and time into strings and concatenate them.
    today = "Accessed at: " + str(datetime.date.today()) + " " + str(current_time)

    return render_template('BmoreGoodFood.html', date=today)


if __name__ == "__main__":
    app.run(debug=True)
