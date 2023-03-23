from flask import Blueprint, render_template, request, flash
from flask_mysqldb import MySQL

from . import dbmysql
from . import dbmongo

auth = Blueprint('auth',__name__)

@auth.route('/login',methods =['GET','POST'])
def login():

    if request.method == 'POST':
        username  =request.form.get('email')
        password =request.form.get('password')
        print(dbmongo)
    
   
    return render_template("login.html")

@auth.route('/logout')
def logout():
    return "<p>logout</p>"

@auth.route('/sign-up',methods =['GET','POST'])
def sign_up():
   
    if request.method == 'POST':
        email =request.form.get('email')
        username  =request.form.get('firstName')
        password =request.form.get('password1')
        password2 =request.form.get('password2')
        
 
        
        cursor = dbmysql.connection.cursor()
        cursor.execute(''' INSERT INTO user VALUES(%s,%s)''',(username ,password))
        dbmysql.connection.commit()
        cursor.close()
        return f"Done!!"
        

    return render_template("sing_up.html")