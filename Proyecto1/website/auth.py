from flask import *
from flask_mysqldb import MySQL
from datetime import datetime
import hashlib
from PIL import Image
import base64
from io import *
from MySQLdb import IntegrityError

from . import dbmysql
from . import dataSetMongo
from . import r


auth = Blueprint('auth',__name__)

@auth.route('/login',methods =['GET','POST'])
def login():

    if request.method == 'POST':
        username  =request.form.get('username')
        password =request.form.get('password')

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        cursor = dbmysql.connection.cursor()
        queryLogin = "SELECT COUNT(*) FROM usuarios WHERE username=%s AND password=%s"
        cursor.execute(queryLogin, (username, hashed_password))
        result = cursor.fetchone()[0]
        if result == 1:
            query = "SELECT * FROM usuarios WHERE username=%s"
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            id = row[0]
            nombreCompleto = row[3]
            fechaNacimietno = row[4]

            query = "SELECT picture_data FROM pictures WHERE id=%s"
            cursor.execute(query, (id,))
            image_data = cursor.fetchone()[0]
            image_buffer = BytesIO(image_data)
            base64_image = base64.b64encode(image_buffer.getvalue()).decode()
            cursor.close()
            return render_template("usuario.html",foto=base64_image,username=username,name=nombreCompleto,fecha=fechaNacimietno)
        else:
            cursor.close()
            flash('Error al ingresar Usuario o constraseña invalida ', 'error')
            return render_template("login.html")
   
    
    
    return render_template("login.html")

@auth.route('/logout')
def logout():
    return "<p>logout</p>"

@auth.route('/sign-up',methods =['GET','POST'])
def sign_up():
    if request.method == 'POST':
        
        username =request.form.get('username')
        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        if not username or not password or not nombre or not fecha or not foto.filename:
            print("DATOS INCOMPLETOS")
            return render_template("sign_up.html")
        else:
            try:
                # Se encrypta la contraseña
                hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

                cursor = dbmysql.connection.cursor()
                # query inserta el usuario en la base de datos
                cursor.execute(''' INSERT INTO usuarios (username, password, nombreCompleto, fechaNacimiento) VALUES(%s,%s,%s,%s)''',(username ,hashed_password,nombre,fecha))
                dbmysql.connection.commit()

                # Se le y parsea la foto para guardar en la base de datos mysql
                img_data = foto.read()
                img_base64 = base64.b64encode(img_data).decode('utf-8')
                img = Image.open(BytesIO(img_data))
                # query insertar la imagen en la base de datos
                query = "INSERT INTO pictures (username,picture_data) VALUES (%s, %s)"
                cursor.execute(query, (username,img_data))
                dbmysql.connection.commit()
                cursor.close()
                return redirect('/')
            
            except IntegrityError as e:
                flash('Error al registrarse '+str(e), 'error')
                return redirect('/')
            
    return render_template("sign_up.html")

@auth.route('/update',methods =['GET','POST'])
def update():

    if request.method == 'GET':
            username = request.args.get('username')
            cursor = dbmysql.connection.cursor()
            query = "SELECT * FROM usuarios WHERE username=%s"
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            password = row[2]
            nombreCompleto = row[3]
            fechaNacimietno = row[4]
            cursor.close()
            return render_template('update.html', username=username,password=password,nombre=nombreCompleto,fecha=fechaNacimietno,foto=None)
    if request.method == 'POST':

        username = request.args.get('username')
        cursor = dbmysql.connection.cursor()
        query = "SELECT password FROM usuarios WHERE username=%s"
        cursor.execute(query, (username,))
        hashPassword = cursor.fetchone()[0]

        password  =request.form.get('password')
        nombre =request.form.get('nombre')
        fecha =request.form.get('fecha')
        foto  = request.files['foto']
        if  foto.filename:
            img_data = foto.read()
            img_base64 = base64.b64encode(img_data).decode('utf-8')
            img = Image.open(BytesIO(img_data))

            query = "UPDATE pictures SET picture_data=%s WHERE username=%s"
            cursor.execute(query, (img_data,username,))
            dbmysql.connection.commit()
          
        if hashPassword != password:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            query = "UPDATE usuarios SET password=%s WHERE username=%s"
            cursor.execute(query, (hashed_password,username,))
            dbmysql.connection.commit()

        query = "UPDATE usuarios SET nombreCompleto=%s, fechaNacimiento=%s WHERE username=%s"
        cursor.execute(query, (nombre,fecha,username,))
        dbmysql.connection.commit()
        

    return render_template('home.html')

        
        
        #id = r.get('id')
        #id = int(id)+1
        #print(dataSetMongo)
        #dataset_doc = { 'id' : id, username : "sebas1498", 'email' : "nombre",'dataset1' : "Esto es una prueba", 'date' : datetime.utcnow()}
        #r.set('id',id)
        #print(id)
        #dataSetMongo.insert_one(dataset_doc)


@auth.route('/home',methods =['GET','POST'])
def logins():

    if request.method == 'POST':
        username  =request.form.get('username')
        password =request.form.get('password')

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        cursor = dbmysql.connection.cursor()
        query = "SELECT COUNT(*) FROM usuarios WHERE username=%s AND password=%s"
        cursor.execute(query, (username, hashed_password))
        result = cursor.fetchone()[0]
        if result == 1:
            print('Login successful') 
        else:
            print('Login successful')
   
    return render_template("home.html")

@auth.route('/dataset')
def dataset():
    if request.method == 'GET':
        username = request.args.get('username')
        return render_template('dataset.html', username=username)
    return render_template('home.html')

@auth.route('/crearDataset',methods =['GET','POST'])
def crearDataset():
     if request.method == 'GET':
        username = request.args.get('username')
        return render_template('crearDataset.html', username=username)
     return render_template('home.html')
     