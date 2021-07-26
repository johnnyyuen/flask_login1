### Login function using Flask

Function included:
1. New User (with password re-enter check)
2. Update Profile (email, password)
3. Delete user with confirmation (inside profile)
4. Keep user session for n days

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
