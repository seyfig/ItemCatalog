# Item Catalog Application


### Item Catalog is a web application, which allows users to do mainly the following:

 * Browse categories, 
 * Show items in categories and recently added items, 
 * Show item details
 * Authenticate users,
 * Enable users to modify their own items
	
### In order to run the web site, it is required to:

 * Have Python 2 installed,
 * Have vagrant installed,
 * Locate application.py, database_setup.py files and templates, static folders in the same folder,
 * Modify client_secrets.json file in order to change application information for Google Plus authentication
 * Modify fb_client_secrets.json file in order to change application information for Facebook authentication
 * Run database_setup.py file
 * Run initialData.py file
 * Run application.py file
	
### Browsing the web site:

 * Browse http://localhost:8000 to view application
 * Categories and items may be selected to view in detail
 * In order to add new item "New Item" link should be clicked from the navigation menu,
    if no user logged in, it will redirect to login page
 * In order to login click "Click Here To Login" link from the navigation menu
 * After logging in, user can add new item
 * After logging in, if item detail page browsed, there will be links for Edit and Delete
 * For JSON API endpoint visit http://localhost:8000/catalog.json
 * For XML API endpoint visit http://localhost:8000/catalog.xml