from flask import (Flask, render_template, request,
                   redirect, url_for, jsonify, flash, make_response)
from flask import session as login_session
import httplib2
import json
import requests
import random
import string

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

from models import Base, Category, Item, User

app = Flask(__name__)

# Pull Google clients from external JSON file.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///catalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/catalog.json')
def JSONCatalog():
    """Return the entire catalog in JSON format"""
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/category<int:category_id>.json')
def JSONCategory(category_id):
    """Return a single category in JSON format"""
    category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(Category=category.serialize)


@app.route('/item<int:item_id>.json')
def JSONItem(item_id):
    """Return a single item in JSON format"""
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/')
def showCategories():
    """Render the home page, or if not logged in, render the public homepage"""
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template(
            'publiccategories.html',
            categories=categories
        )
    else:
        return render_template('categories.html', categories=categories)


@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    """On a GET request, render the New Category webpage.
    On a POST request, create a new category in the catalog."""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name'].isspace() or len(request.form['name']) == 0:
            flash("Category name must have length and characters")
            return redirect(url_for('showCategories'))
        newCategory = Category(name=request.form['name'])
        session.add(newCategory)
        session.commit()
        flash("New Category Created")
        return redirect(url_for('showCategories'))
    else:
        return render_template('newcategory.html')


@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    """On a GET request, render the Edit Category webpage.
    On a POST request, edit an existing category in the catalog."""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            if request.form['name'].isspace() \
              or len(request.form['name']) == 0:
                flash("Category name must have length and characters")
                return redirect(url_for('showCategories'))
            category.name = request.form['name']
        session.add(category)
        session.commit()
        flash("Category Edited")
        return redirect(url_for('showCategories'))
    else:
        return render_template('editcategory.html', category=category)


@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """On a GET request, render the Delete Category webpage.
    On a POST request, delete a category and all its items from the catalog."""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    if request.method == 'POST':
        session.delete(category)
        for i in items:
            session.delete(i)
        session.commit()
        flash("Category Deleted")
        return redirect(url_for('showCategories'))
    else:
        return render_template('deletecategory.html', category=category)


@app.route('/category/<int:category_id>')
def showItems(category_id):
    """Render the item page, or if not logged in,
    render the public item page"""
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('publicitem.html',
                               category=category,
                               items=items)
    else:
        return render_template('item.html', category=category, items=items)


@app.route('/category/<int:category_id>/item/new', methods=['GET', 'POST'])
def newItem(category_id):
    """On a GET request, render the new item page.
    On a POST request, create a new item."""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name'].isspace() or len(request.form['name']) == 0:
            flash("Category name must have length and characters")
            return redirect(url_for('showItems', category_id=category.id))
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id
        )
        session.add(newItem)
        session.commit()
        flash("New Item Created")
        return redirect(url_for('showItems', category_id=category.id))
    else:
        return render_template('newitem.html', category=category)


@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    """On a GET request, return the edit item page.
    On a POST request, modify an existing item."""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if login_session['user_id'] != item.user_id:
            flash("You may only edit items you created.")
            return redirect(url_for('showItems', category_id=category.id))
        if request.form['name'].isspace() or len(request.form['name']) == 0:
            flash("Category name must have length and characters")
            return redirect(url_for('showItems', category_id=category.id))
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash("Existing Item Edited")
        return redirect(url_for('showItems', category_id=category.id))
    else:
        return render_template('edititem.html', category=category, item=item)


@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    """On a GET request, render the delete item confirmation page.
    On a POST request, delete an item in the catalog."""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if login_session['user_id'] != item.user_id:
            flash("You may only delete items you created.")
            return redirect(url_for('showItems', category_id=category.id))
        session.delete(item)
        session.commit()
        flash("Existing Item Deleted")
        return redirect(url_for('showItems', category_id=category.id))
    else:
        return render_template('deleteitem.html',
                               category=category, item=item)


@app.route('/login')
def showLogin():
    """Render the login page."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """On a POST request, reach out to Google for OAuth login"""
    # Validate the state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    (resp_headers, content) = h.request(url, 'GET')
    result = json.loads(content.decode('utf-8'))
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's Client ID doesn't match."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])

    # If the user does not yet exist, create it.
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = '<h1>Welcome! You are now logged in as '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '">'

    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/disconnect')
def disconnect():
    """Logout"""
    # Is the user logged in?
    if 'username' in login_session:
        access_token = login_session.get('access_token')
        if access_token is None:
            response = make_response(
                json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
            % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]

        # If the logout was successful, delete their session
        if result['status'] == '200':
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']

            flash("You have successfully been logged out.")
            return redirect(url_for('showCategories'))
        else:
            flash('Error 400: Failed to revoke token for given user.')
            return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


def createUser(login_session):
    """Create a user"""
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'],
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Return the user object when provided a user_id"""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """When provided an email, return the user.id
    or None if the user doesn't exist."""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
