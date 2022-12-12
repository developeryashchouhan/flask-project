import os
import time
import pandas as pd
import json
from flask import Flask, request, jsonify, make_response, request, render_template, session,flash
from flask import redirect,url_for,session,send_file
import jwt
from datetime import date, datetime, timedelta
from functools import wraps
from configparser import ConfigParser
from flask_mysqldb import MySQL
import secrets
from werkzeug.utils import secure_filename 
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_migrate import Migrate
from wtforms.validators import DataRequired, Length
from wtforms import StringField,  SubmitField
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer as Serializer
import smtplib
import ssl


app = Flask(__name__)
app.config["DEBUG"] = True
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:root@localhost/data_validation'
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
# app.config['MAIL_SERVER']='smtp@gmail.com'
# app.config['MAIL_PORT']=587
# app.config['MAIL_USE_TLS']=True
# app.config['MAIL_USERNAME']='yash100chouhan@gmail.com'
# app.config['MAIL_PASSWORD']='qfgcupcdjotabklg'
Session(app)
 
# mail=Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
# app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(hours=2)
# jwt = JWTManager(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view= 'login'

# Intialize MySQL
mysql = MySQL(app)
#UPLOAD_FOLDER = 'static\\file'



basedir = os.path.abspath(os.path.dirname(__file__))
a=os.path.basename(os.path.dirname(__file__))
dirname=os.path.dirname(__file__)
# print("dirname-",dirname)
#b=os.path.commonpath(os.path.dirname(__file__))


UPLOAD_FOLDER = os.path.join(basedir,'/')
app.config['UPLOAD_FOLDER'] =  UPLOAD_FOLDER

# print("upload_folder=",UPLOAD_FOLDER)
# print("basedir=",basedir)


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key =True)
    username = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), nullable= False)
    password = db.Column(db.String(150), nullable = False)
    role = db.Column(db.String(15))

    
    def __init__(self,username,email,password,role) :
        self.username=username
        self.email=email
        self.password=password
        self.role=role

    def __repr__(self):
            return '<User %r>' % self.username

    
    def get_token(self):
        serial=Serializer(app.config['SECRET_KEY'])
        return serial.dumps({'id':self.id}).encode().decode ('utf-8') 
    
    @staticmethod
    def verify_token(token):
        
        serial=Serializer(app.config['SECRET_KEY'])
        print("serial",serial)
        try:
            id=serial.loads(token)['id']
            print("id",id)
        except:
            return None
        return User.query.get(id)         
 


   
#with app.app_context():
#     db.create_all()

#     db.session.add(User('admin', 'admin@example.com','12345','user'))
#     db.session.add(User('guest', 'guest@example.com','12345','user'))
#     db.session.add(User('yash123', 'yash100chouhan@gmail.com','12345','admin'))
#     db.session.commit()

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

class ResetRequestForm(FlaskForm):
    email= StringField('email', validators=[InputRequired(), Length(min=5, max=45)])
    reset = SubmitField('reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=10)])
    confirm_password = PasswordField('confirm_password', validators=[InputRequired(), Length(min=5, max=10)])
    submit = SubmitField('submit') 

class LoginForm(FlaskForm):
	username= StringField('username', validators=[InputRequired(), Length(min=5, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=10)])
	remember = BooleanField('Remember me')


class RegisterationForm(FlaskForm):
	email= StringField('Email', validators=[InputRequired(),Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=5, max=15)])

class UpdateForm(FlaskForm):
   
    email = StringField('email',Email(message=('Not a valid email address.')),[DataRequired()])
    username = StringField('username',[DataRequired()])
    submit = SubmitField('Submit')
     



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        #token=request.args.get('token')
        #print("decorator token--->",login.token)
        id=session.get("id")
        # print("ID==",public_id)
        token=session.get("token")
        
    #    if  request.headers:
    #         token = request.headers.get['X_Access_Token']
    #         token=request.headers.get('X-Access-Token')
    #         print("token inside if===>",token)

        if not token:
            return jsonify({'message' : 'Unauthorized Access'}), 401
        if token:
    
            #token = request.headers.get('X-Access-Token')
            #print("token inside if===>",token)
            try:
                #data = jwt.decode(token, app.config['SECRET_KEY'])
                data=token.encode().decode("utf-8")
                print("data encode",data)
                current_user = User.query.filter_by(id=id).first()
                print("curent user ",current_user)
            except:
                return jsonify({'message': 'Something is missing in token'}), 401

            return f(current_user, *args, **kwargs)
    return decorated 


def send_mail(user):
    token=user.get_token()
    smtp_port = 587                 
    smtp_server = "smtp.gmail.com"  

    email_from = "yash100chouhan@gmail.com"
    email_to = "yash100chouhan@gmail.com"

    pswd = "qfgcupcdjotabklg"



    message = f'''To reset ur password click on link


           {url_for('reset_token',token=token,_external=True)}



            IF YOU DID'NT SEND A PASSWORD RESET REQUEST. PLEASE IGNORE THIS MESSAGE
   
   
   '''


    simple_email_context = ssl.create_default_context()
    try:
  
        print("Connecting to server...")
        TIE_server = smtplib.SMTP(smtp_server, smtp_port)
        TIE_server.starttls(context=simple_email_context)
        TIE_server.login(email_from, pswd)
        print("Connected to server :-)")
        
    
        print()
        print(f"Sending email to - {email_to}")
        TIE_server.sendmail(email_from, email_to, message)
        print(f"Email successfully sent to - {email_to}")


    except Exception as e:
        print(e)


    finally:
     TIE_server.quit()


@app.route('/reset_password',methods=['GET','POST'])
def reset_request():
    form=ResetRequestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
    
        if user:
            send_mail(user)
            print("message sent successfully!!!")
            flash('Reset request sent. Check your mail. ','success')
            return redirect(url_for('login'))
            
    return render_template('reset_request.html',title='reset request',form=form)


@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
    user= User.verify_token(token)
    if user is None:
        flash('That is invalid token or expired','warning')
        return redirect(url_for('reset_request'))
    form=ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method= 'sha256')
        user.password=hashed_password
        db.session.commit()
        print("password changed")
        flash('password changed! please login!','success')
        return redirect(url_for('login'))
    return render_template('change_password.html',form=form)
          



@app.route('/', methods=['GET', 'POST']) 
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data ).first()
        if not user:
            # return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'})
            msg="Invalid User Name and Password"        
            return render_template('login.html',msg=msg,form=form)
        if user:    
            if check_password_hash(user.password, form.password.data):
                    
                login_user(user, remember=form.remember.data)
                user1 = User.query.filter_by(username=form.username.data ).all()
                for data in user1:
                    if data.role =="admin":
                        session['logged_in']=True
                        token = jwt.encode({'id' : data.id,'exp' : datetime.utcnow() + timedelta(seconds=10)},app.config['SECRET_KEY'], "HS256")

                        session['id']=data.id
                        session['token']=token
                    
                    
                        # response = redirect(url_for('admindashboard'))
                        # print("response--->",response)
                        # response.headers['x_access_token'] = token.encode().decode("utf-8")
                        # print('Response header====>', response.headers)
                        # return response
                        # return response_builder(url_for('admindashboard'), token)
                        #return jsonify({'token':token.encode().decode("utf-8")})
                        return redirect(f"/admindashboard")
                        
                                
                    else:
                        
                        session['logged_in']=True
                        token = jwt.encode({'id' : data.id,'exp' : datetime.utcnow() + timedelta(seconds=10)},app.config['SECRET_KEY'], "HS256")
                        print("login token===>",token)
                        session['id']=data.id
                        session['token']=token
                        return redirect(f"/userdashboard")
                        # access_token = create_access_token(identity=data.username)
                        # refresh_token = create_refresh_token(identity=data.username)
                        # return jsonify(access_token=access_token, refresh_token=refresh_token)

                msg="Invalid User Name and Password"        
                return render_template('login.html',msg=msg,form=form)
             
            
            
    user1 = User.query.filter_by(username=form.username.data ).all()
    return render_template('login.html',form=form,user=user1)
         
@app.route('/admindashboard',methods=['GET','POST'])
@token_required
@login_required
def admindashboard(current_user):
    if current_user:
        pass
    return render_template("admindashboard.html")


@app.route('/userdashboard',methods=['GET','POST'])
@token_required
@login_required
def userdashboard(current_user):
    return render_template("userdashboard.html")    

# signup route
@app.route('/signup', methods =['POST','GET'])
@login_required
def signup():
	
	
    form = RegisterationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if not user:
            user = User(
                username = form.username.data,
                email = form.email.data,
                password = generate_password_hash(form.password.data, method= 'sha256'),
                role='user'
            )
            db.session.add(user)
            db.session.commit()
            msg="Successfully registered"
            return render_template('signup.html', form=form,msg=msg)
           
        else:
          
            msg="User already exists. Please Log in."
            return render_template('signup.html', form=form,msg=msg)

    return render_template('signup.html', form=form)

@app.route('/manageusers',methods=['GET'])
@login_required

def manageusers():
    userDetails=User.query.all() 
    print(userDetails)
    return render_template('manageusers.html',userDetails=userDetails)

@app.route('/update/<int:id>',methods=['GET'])
@login_required

def updateRoute(id):

    if not id or id != 0:
        Entry = User.query.get(id)
        if Entry:
            userDetails=User.query.filter_by(id=id).all()
            return render_template('update.html', userDetails=userDetails)

    

@app.route('/update/<int:id>', methods=['POST','PUT'])
@login_required

def update(id):
    if not id or id != 0:
        userDetails = User.query.get(id)
    
        if userDetails:
            
            new_email = request.form.get('email')
            new_username = request.form.get('username')
            print(new_email,new_username)
            userDetails.email = new_email
            userDetails.username = new_username
            db.session.commit()
        msg="Successfully Updated"
        userDetails=User.query.all()
        return render_template('manageusers.html', msg=msg,userDetails=userDetails)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if not id or id != 0:
        userDetails = User.query.get(id)
        if userDetails:
            db.session.delete(userDetails)
            db.session.commit()
        msg="Deleted Successfully "
        return render_template('manageusers.html', msg=msg)

@app.route('/logout') 

def logout():
	logout_user()
	return redirect(url_for('login'))



#Data Validation source selection
@app.route('/data_validation',methods=['POST','GET'])
@login_required


def data_validation():
        if request.form["Submitbutton"]=='SingleDataSource':
            return render_template('SingleDataSource.html')
        else:
            return render_template('DoubleDataSource.html')
    
#Single Data Source Validation
@app.route("/SingleDataSource", methods=['POST','GET'])
@login_required


def SingleDataSource():
    parser = ConfigParser()
    
    try:
     
        data_source_type = request.form['datasourcetype']
        
        if data_source_type=='CSV':             
                        
            #file_path = request.form['DataSourcePath'] 
            file = request.files['DataSourcePath']
            print("file=",file) 
            filename = secure_filename(file.filename)
            print("filename",filename)
            #print(os.path.join(app.config['UPLOAD_FOLDER'])
            file_path=os.path.join(basedir, file.filename)
            #print("f=",f)
            #file_path=file.save(f)
            print("file path =",file_path)          
             
            delimiter = request.form['Delimiter']
            #print("delimeter",delimiter) 

            #file_name = os.path.basename(file_path)
            #print("file name",file_name) 

            output_file_path = request.form['output_file_path']
            #print("output_file_path",output_file_path) 

            data = pd.read_csv(file_path)
            #print(data) 

            col_list = list(data.columns)
            #print("col list",col_list) 

            data_type_list = list(data.iloc[1])
           # print("data type list",data_type_list)

         
        try:
            #for creating config file   
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:    
                file.write("")  
            parser.add_section("APP")            
            parser.set("APP",'RULE_FILE_PATH',os.getcwd()+"\\rule_file.json")
            parser.set("APP",'SOURCE_TYPE',data_source_type)
            parser.set("APP",'OUTPUT_FILE',output_file_path)
            parser.add_section("SOURCE")
            parser.set("SOURCE","SOURCE_DATA_FILE_PATH", file_path)
            parser.set("SOURCE","Delimiter", delimiter)
           
            with open("C:\\rulengine_master\configuration.ini", 'w') as file: 
                parser.write(file)

        except:
             print(Exception)
             raise

        return render_template('rule_file_generator.html',file_path=file_path,data=data,file_name = filename, col_list=col_list,datatype_list=[get_datatype(data) for data in data_type_list],len = len(col_list))
    except:
        print(Exception)
        raise
    

@app.route("/create", methods=['POST'])
@login_required 



def create_json():
        
    json_object = []
    try:
        i=1
        while True:
            Dict = {"RuleID": "" + str(i) + "",
            "RuleName": request.form[f"name{i}"] + " validation",            
            "DataAttribute": request.form[f'data_attribute{i}'],
            "DataType": request.form[f'datatype{i}'],
            "ValidationOperator": request.form[f'valop{i}'],
            "ValueToBeMatch": request.form[f'valtomatch{i}'],
            "Order": request.form[f'order{i}'],
            "DataObject":request.form['DataObject'],
            "DataSource":request.form['DataSource'],
            "Sequence":request.form[f'order{i}']
            
            }
            json_object = AddToJSON(json_object, Dict)
            i+=1
    except: 
        with open ('rule_file.json','w') as f:
            f.write(json.dumps(json_object,indent=4))    
            
            
       
        
        return render_template('download.html')


def AddToJSON(json_object, myDict):
    # Data to be written
    
    json_object.append(myDict)
    return json_object


def get_datatype(col_name):
    if type(col_name)==str:
        return 'String'
    if type(col_name.item())==int:
        return 'Integer'
    if type(col_name.item())==float:
        return 'Float'
    if type(col_name.item())==time:
        return 'Time'
    if type(col_name.item())==date:
        return 'Date'


@app.route("/download")
@login_required
def download_file():
    downloaded_file="rule_file.json"
    return send_file(downloaded_file,as_attachment=True)


# DOuble Data Source Validation
@app.route("/DoubleDataSource", methods=['POST','GET']) 
@login_required

def DoubleDataSource():
    
    parser = ConfigParser()
    try:
        with open("C:\\rulengine_master\configuration.ini", 'w') as file:
            file.write("")  
        output_file_path = request.form['output_file_path'] 
        
        

        data_source_type = request.form['datasourcetype']

        
        
        if data_source_type == 'CSV':

            file1 = request.files['DataSourcePath1'] 
            filename1=secure_filename(file1.filename)
            file_path1=os.path.join(basedir, file1.filename)
            delimiter1 = request.form['Delimiter1']
            
            parser.add_section("APP")
            parser.set("APP",'SOURCE_TYPE',data_source_type)
            parser.set("APP",'OUTPUT_FILE',output_file_path)
            parser.add_section("SOURCE")
            parser.set("SOURCE","SOURCE_DATA_FILE_PATH", file_path1)
            parser.set("SOURCE","Delimiter", delimiter1)
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)
            
        if data_source_type == 'JSON':
            file_path1 = request.form['DataSourcePath1'] 
            parser.add_section("APP")
            parser.set("APP",'SOURCE_TYPE',data_source_type)
            parser.set("APP",'OUTPUT_FILE',output_file_path)
            parser.add_section("SOURCE")
            parser.set("SOURCE","SOURCE_DATA_FILE_PATH", file_path1)
            
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)

        if data_source_type == 'XLSX':
            file_path1 = request.form['DataSourcePath1'] 
            sheet_no1 = request.form['sheet_no1'] 
            skip_rows1 = request.form['skip_rows1'] 

            parser.add_section("APP")
            parser.set("APP",'SOURCE_TYPE',data_source_type)
            parser.set("APP",'OUTPUT_FILE',output_file_path)
            parser.add_section("SOURCE")
            parser.set("SOURCE","SOURCE_DATA_FILE_PATH", file_path1)
            parser.set("SOURCE","SHEET_NO", sheet_no1)
            parser.set("SOURCE","SKIP_ROWS", skip_rows1)
  
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)

        if data_source_type == 'ORACLE' or data_source_type == 'MYSQL':
            server1 = request.form['Server1'] 
            database1 = request.form['Database1'] 
            user1 = request.form['user1'] 
            password1 =file_path = request.form['password1'] 
            schema_name1 = request.form['schema_name1']            
            source_query_filter1 = request.form['source_query_filter1'] 
            parser.add_section("APP")
            parser.set("APP",'SOURCE_TYPE',data_source_type)
            parser.set("APP",'OUTPUT_FILE',output_file_path)
            parser.add_section("SOURCE")
            parser.set("SOURCE","SERVER", server1)
            parser.set("SOURCE","DATABASE", database1)
            parser.set("SOURCE","USER", user1)
            parser.set("SOURCE","PASSWORD", password1)
            parser.set("vTurbineMasterData","SCHEMA_NAME", schema_name1)
            parser.set("vTurbineMasterData","SOURCE_QUERY_FILTER",source_query_filter1)

            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)
         
        # data dest 
        data_source_type = request.form['datadesttype']
        parser.set("APP",'DEST_TYPE',data_source_type)

        if data_source_type == 'CSV':

            file2 = request.files['datasourcepath2'] 
            filename2=secure_filename(file2.filename)
            file_path2=os.path.join(basedir, file2.filename)
            delimiter1 = request.form['Delimiter1']
           
            delimiter2 = request.form['delimiter2']
           
            
            
            parser.add_section("DEST")
            parser.set("DEST","DEST_DATA_FILE_PATH", file_path2)
            parser.set("DEST","Delimiter", delimiter2)
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)
           
        if data_source_type == 'JSON':
            file_path2 = request.form['datasourcepath2'] 

            parser.add_section("DEST")
            parser.set("DEST","DEST_DATA_FILE_PATH", file_path2)
         
            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)


        


        if data_source_type == 'XLSX':
            file_path2 = request.form['DataSourcePath2'] 
            sheet_no2 = request.form['sheet_no2'] 
            skip_rows2 = request.form['skip_rows2']

            parser.add_section("DEST")
            parser.set("DEST","DEST_DATA_FILE_PATH", file_path2)
            parser.set("DEST","SHEET_NO", sheet_no2)
            parser.set("DEST","SKIP_ROWS", skip_rows2)

            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)


        if data_source_type == 'ORACLE' or data_source_type == 'MYSQL':
            server2 = request.form['Server2'] 
            database2 = request.form['Database2'] 
            user2 = request.form['user2'] 
            password2 = request.form['password2'] 
            schema_name2 = request.form['schema_name2']            
            source_query_filter2 = request.form['source_query_filter2'] 
        
            parser.add_section("DEST")
            parser.set("DEST","SERVER", server2)
            parser.set("DEST","DATABASE", database2)
            parser.set("DEST","USER", user2)
            parser.set("DEST","PASSWORD", password2)

            parser.add_section("vTurbineMasterData")
            parser.set("vTurbineMasterData","SCHEMA_NAME", schema_name2)
            parser.set("vTurbineMasterData","SOURCE_QUERY_FILTER",source_query_filter2)

            with open("C:\\rulengine_master\configuration.ini", 'w') as file:
                parser.write(file)
        
        
        return "success"
    except:
        print(Exception)
        raise
        

#app run
if (__name__ == "__main__"):
     app.run()



