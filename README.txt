# Item Catalog; a collaborative item catelog in which all users have permission to edit any item once logged in. 

IP Address: 54.83.187.17
SSH Port: 2222
URL: http://newb.devcubator.com/

Installed Software:
* Apache
* PostgreSQL
* Ubuntu

Configurations Made:

# Dependencies
- [python3](https://www.python.org/download/releases/3.0/)
- flask
- httplib2
- json
- requests
- random
- string
- sqlalchemy
- sqlalchemy.orm
- sqlalchemy.ext.declarative
- oauth2client.client

# How to use this application
## Create your own Google Developer account at https://developers.google.com/
- Download your client secrets as a JSON blob and save it as client_secrets.json in the same directory as your application.py file.

## Installing the VM
- Use GitBash, or a similar CLI. 
- Download & install [vagrant](https://www.vagrantup.com/downloads.html)
- Descend into it with `cd vagrant`
- Start up your new virtual machine with `vagrant up`
- SSH into your VM with `vagrant ssh`



# Running the application. 
- No installation required
- Descend into the file to which you have extracted this script.
- Run the command 'python application.py'
- Visit localhost:8000 in order to access the application.

A file named catalog.db will be created the first time you run this program which will contain your new database.


# CONTRIBUTING
### Creator:
 - Danielle Copley
 - Udacity.com API and OAuth training example code
### Honorable Mentions:
 - Hostgator.com

