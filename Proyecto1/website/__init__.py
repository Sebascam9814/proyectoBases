from flask import Flask
from flask_mysqldb import MySQL
from pymongo  import MongoClient

dbmysql = MySQL()
dbmongo =  MongoClient(host="localhost", port=27017)


def create_app():
    app = Flask(__name__)

    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = ''
    app.config['MYSQL_DB'] = 'web'
    
    app.config['MONGODB_SETTINGS'] = {
    'db': 'your_database',
    'host': 'localhost',
    'port': 27017
}
    
    
    dbmysql.init_app(app)
    

   

    from .views import views
    from .auth import auth


    app.register_blueprint(views,url_prefix='/')
    app.register_blueprint(auth,url_prefix='/')

    return app


### Fuentes
#  https://www.youtube.com/watch?v=dam0GPOAvVI&t=2421s
#  https://hevodata.com/learn/flask-mysql/
#
#
# pip install Flask
#  pip install pymongo
# pip install flask_mysqldb

# https://lucid.app/lucidchart/2d36ee22-0bae-425e-9219-3ca660e52d6f/edit?viewport_loc=-160%2C3%2C1819%2C855%2C0_0&invitationId=inv_a92af070-0a7a-43f3-a987-c9cc87fd15b2