from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import make_response, Response, flash
from flask import session as login_session
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import xml.etree.ElementTree as ET
import os
from werkzeug import secure_filename

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"
app.config['UPLOAD_FOLDER'] = os.getcwd() + '/static/pictures'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Start Authentication


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def createResponse(message, httpResultCode):
    response = make_response(json.dumps(message), httpResultCode)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        return createResponse('Invalid state parameter.', 401)
    access_token = request.data

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
        app_id,
        app_secret,
        access_token
        )
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    # , let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    return login()


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id,
        access_token
    )
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        return createResponse('Invalid state parameter.', 401)
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return createResponse('Failed to upgrade the authorization code.', 401)

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return createResponse('error', 500)
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return createResponse(
            "Token's user ID doesn't match given user ID.",
            401
        )
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return createResponse("Token's client ID does not match app's.", 401)

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        return createResponse('Current user is already connected.', 200)

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
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    return login()


@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
	# Not Connected
    if credentials is None:
        return createResponse('Current user not connected.', 401)
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # Invalid Token
    if result['status'] != '200':
        return createResponse('Failed to revoke token for given user.', 400)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.", category='Success')
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'), category='Warning')

# END Authentication
# START User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def login():
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; '
    output += ' -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash(
        "Now logged in as %s" % login_session['username'],
        category='Success'
    )
    return output

# END User Helper Functions
# START EndPoint APIs


# JSON API to view Catalog Information
@app.route('/catalog.json')
def catalogJSON():
    Categories = session.query(Category).order_by(asc(Category.name)).all()
    Cat = []
    for category in Categories:
        items = session.query(Item).filter_by(category_id=category.id).all()
        if items and len(items) > 0:
            c = {
                'id': category.id,
                'name': category.name,
                'Item': [i.serialize for i in items],
            }
        else:
            c = {
                'id': category.id,
                'name': category.name,
            }
        Cat.append(c)
    return jsonify(Category=Cat)


# XML API to view Catalog Information
@app.route('/catalog.xml')
def catalogXML():
    root = ET.Element('Categories')
    Categories = session.query(Category).order_by(asc(Category.name)).all()
    for category in Categories:
        categoryElemenet = ET.SubElement(root, 'category')
        categoryElemenet.attrib['name'] = category.name
        cat_id = ET.SubElement(categoryElemenet, 'id')
        cat_id.text = str(category.id)
        itemsElement = ET.SubElement(categoryElemenet, 'Item')
        items = session.query(Item).filter_by(category_id=category.id).all()
        for item in items:
            itemElement = ET.SubElement(itemsElement, 'item')
            itemElement.attrib['title'] = item.title
            item_id = ET.SubElement(itemElement, 'id')
            item_id.text = str(item.id)
            item_description = ET.SubElement(itemElement, 'description')
            item_description.text = item.description
            item_cat_id = ET.SubElement(itemElement, 'cat_id')
            item_cat_id.text = str(category.id)
    output = ET.tostring(root, method="xml")
    output = '<?xml version="1.0" encoding="UTF-8"?>' + output
    return app.response_class(output, mimetype='application/xml')

# END EndPoint APIs
# START Category, Item


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    Categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(12)
    return render_template(
        'showcategory.html',
        categories=Categories,
        items=items
    )


# Show a category
@app.route('/catalog/<string:category_name>/')
def showCategory(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    if category:
        Categories = session.query(Category).order_by(asc(Category.name)).all()
        items = session.query(Item).filter_by(
            category_id=category.id
        ).order_by(desc(Item.id)).all()
        return render_template(
            'showcategory.html',
            items=items,
            categories=Categories,
            category=category
        )


# Create a new menu item
@app.route('/catalog/item/new', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    Categories = session.query(Category).order_by(asc(Category.name)).all()
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category_name']
        ).one()
        if not request.form['title']:
            flash('Title can not be empty for new item', category='Danger')
            return render_template('newitem.html', categories=Categories)
        if category:
            item = Item(
                    title=request.form['title'],
                    description=request.form['description'],
                    category_id=category.id,
                    user_id=login_session['user_id']
            )
            photo = request.files['photo']
            bin_data = photo.read()
            item.photo = bin_data
            try:
                session.add(item)
                session.commit()
                flash(
                    'New Menu %s Item Successfully Created'
                    % (item.title),
                    category='Success'
                )
                return redirect(
                    url_for(
                        'showCategory',
                        category_name=item.category.name
                    )
                )
            except IntegrityError:
                flash(
                    'An item with same title exists.'
                    'Item titles must be unique.',
                    category='Danger'
                )
                session.rollback()
                return render_template('newitem.html', categories=Categories)
        else:
            flash('Category not selected for new item', category='Danger')
            return render_template('newitem.html', categories=Categories)
    else:
        return render_template('newitem.html', categories=Categories)


# Show an item
@app.route('/catalog/<string:category_name>/<string:item_title>')
def showItem(category_name, item_title):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(
        category_id=category.id
    ).filter_by(title=item_title).one()
    if item:
        isCreator = False
        if (
            'user_id' in login_session and
            item.user_id == login_session['user_id']
        ):
            isCreator = True
        Categories = session.query(Category).order_by(asc(Category.name)).all()
        return render_template(
            'showitem.html',
            item=item,
            categories=Categories,
            category=None,
            isCreator=isCreator
        )


# Edit item
@app.route('/catalog/<string:item_title>/edit', methods=['GET', 'POST'])
def editItem(item_title):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(title=item_title).first()
    category = item.category
    Categories = session.query(Category).order_by(asc(Category.name)).all()
    if login_session['user_id'] != item.user_id:
        flash(
            'You are not authorized to this item.'
            'You can only edit your own items.',
            category='Warning'
        )
        if category:
            return redirect(
                url_for(
                    'showCategory',
                    category_name=category.name
                )
            )
        else:
            return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        try:
            if request.form['title']:
                item.title = request.form['title']
            if request.form['description']:
                item.description = request.form['description']
            if request.form['category_name']:
                category = session.query(Category).filter_by(
                    name=request.form['category_name']
                ).one()
                if category:
                    item.category = category
            if request.files['photo']:
                photo = request.files['photo']
                bin_data = photo.read()
                item.photo = bin_data
            session.add(item)
            session.commit()
            flash(
                'Item %s Successfully Edited' % item.title,
                category='Success'
            )
            return redirect(
                url_for(
                    'showCategory',
                    category_name=category.name
                )
            )
        except IntegrityError:
            flash(
                'An item with same title exists.'
                'Item titles must be unique.',
                category='Danger'
            )
            session.rollback()
            return render_template(
                'edititem.html',
                item=item,
                categories=Categories,
                category=category
            )
    else:
        return render_template(
            'edititem.html',
            item=item,
            categories=Categories,
            category=category
        )


# Delete item
@app.route('/catalog/<string:item_title>/delete', methods=['GET', 'POST'])
def deleteItem(item_title):
    # First check for CSRF if POST request
    if request.method == 'POST':
        # Prevent CSRF, if token not exists in session or request
        if 'csrf_token' not in login_session or not request.form['csrf_token']:
            return createResponse('Invalid request.', 403)
        # Prevent CSRF, tokens are different
        elif login_session['csrf_token'] != request.form['csrf_token']:
            return createResponse('Invalid request.', 403)
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(title=item_title).first()
    category = item.category
    if login_session['user_id'] != item.user_id:
        flash(
            'You are not authorized to delete this item.'
            'You can only delete your own items.',
            category='Warning'
        )
        if category:
            return redirect(
                url_for(
                    'showCategory',
                    category_name=category.name
                )
            )
        else:
            return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item %s Successfully Deleted' % item_title, category='Success')
        if category:
            return redirect(
                url_for(
                    'showCategory',
                    category_name=category.name
                )
            )
        else:
            return redirect(url_for('showCatalog'))
    else:
        Categories = session.query(Category).order_by(
            asc(Category.name)
        ).all()
        # Prevent CSRF, create a token and send to view
        csrf_token = ''.join(
                        random.choice(
                            string.ascii_uppercase + string.digits
                        )
                        for x in xrange(32)
                        )
        login_session['csrf_token'] = csrf_token
        return render_template(
            'deleteitem.html',
            item=item,
            categories=Categories,
            category=category,
            csrf_token=csrf_token
        )


# Diplay photo of an item
@app.route('/catalog/<string:item_title>/photo')
def photoItem(item_title):
    item = session.query(Item).filter_by(title=item_title).first()
    if item:
        return app.response_class(
            item.photo,
            mimetype='application/octet_stream'
        )

# End Category, Item


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
