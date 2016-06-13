from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, User

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create dummy user
User1 = User(name="Seyfi Bigeye", email="seyfig@seyfig.com",
             picture='')
session.add(User1)
session.commit()

print "added one user!"

# Menu for UrbanBurger
category1 = Category(user_id=1, name="Soccer")
session.add(category1)
category2 = Category(user_id=1, name="Basketball")
session.add(category2)
category3 = Category(user_id=1, name="Baseball")
session.add(category3)
category4 = Category(user_id=1, name="Frisbee")
session.add(category4)
category5 = Category(user_id=1, name="Snowboarding")
session.add(category5)
category6 = Category(user_id=1, name="Rock Climbing")
session.add(category6)
category7 = Category(user_id=1, name="Skating")
session.add(category7)
category8 = Category(user_id=1, name="Hockey")
session.add(category8)
session.commit()

print "added categories!"

item1 = Item(
    user_id=1,
    title="Basketball Ball",
    description="Excellent ball",
    category_id=2
)
session.add(item1)
session.commit()

item2 = Item(
    user_id=1,
    title="Basketball Shoes",
    description="Excellent shoes",
    category_id=2
)
session.add(item2)
session.commit()

print "added two items!"
