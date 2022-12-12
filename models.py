from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key =True)
    username = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), nullable= False)
    password = db.Column(db.String(150), nullable = False)
    role = db.Column(db.String(15))

    def __init__(self,username,email,password) :
        self.username=username
        self.email=email
        self.password=password
        self.role='user'

        

    