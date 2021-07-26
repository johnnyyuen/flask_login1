### Login function using Flask

Package to include:
flask flask_bootstrap flask-login flask-wtf wtforms flask-sqlalchamy email_validator

Points to note:
1. Remeber to put your Secret Key and Database URI into the .env
	e.g. <br />
>PY_SECRET_KEY = "Thisisasecretkey" <br />
>DATABASE_URL = "sqlite:///database.db"


2. DB setup for the app (SQLite3)<br />
`python`  
`from app import db`  
`db.create_all()`
