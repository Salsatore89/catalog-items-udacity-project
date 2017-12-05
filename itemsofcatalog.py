from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup_catalog import Base, CatalogItem, Category, User

engine = create_engine('sqlite:///catalogitem.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# User 1
user1 = User(name="Alex", email="test@gmail.com", picture="https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png")
session.add(user1)
session.commit()


# User 2
user2 = User(name="Veronica", email="test@hotmail.com", picture="https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png")
session.add(user2)
session.commit()


# Items for Snowboard
category1 = Category(name="Snowboarding", user=user1)

session.add(category1)
session.commit()

catalogItem1 = CatalogItem(name="Snowboard", description="Size and shape variances in the boards accommodate for different snow conditions and riding styles. Shorter boards are typically considered youth size and designed for use by children, though some varieties of short boards are specifically designed for a special purpose, such as the performance of snowboarding tricks. Such tricks may take place in a snowpark alongside freestyle skiers.",
                     category=category1, user=user1)

session.add(catalogItem1)
session.commit()

catalogItem2 = CatalogItem(name="Gloves", description="Choosing the best snowboard gloves for you is a lot like the search for the best jacket and pants. Things to consider include fit, style, and suitability to the conditions.",
                     category=category1, user=user1)

session.add(catalogItem2)
session.commit()


# Items for Soccer
category2 = Category(name="Soccer", user=user1)

session.add(category2)
session.commit()


catalogItem1 = CatalogItem(name="Ball", description="A football, soccer ball, or association football ball is the ball used in the sport of association football. The name of the ball varies according to whether the sport is called football, soccer, or association football. The ball's spherical shape, as well as its size, weight, and material composition, are specified by Law 2 of the Laws of the Game maintained by the International Football Association Board.",
                     category=category2, user=user1)

session.add(catalogItem1)
session.commit()

catalogItem2 = CatalogItem(name="Boots", description="Football boots, called cleats or soccer shoes in North America,[1] are an item of footwear worn when playing football. Those designed for grass pitches have studs on the outsole to aid grip. From simple and humble beginnings football boots have come a long way and today find themselves subject to much research, development, sponsorship and marketing at the heart of a multi-national global industry.",
                     category=category2, user=user1)

session.add(catalogItem2)
session.commit()

# Items for Hockey
category3 = Category(name="Hockey", user=user2)

session.add(category3)
session.commit()


catalogItem1 = CatalogItem(name="Stick", description="An ice hockey stick is a piece of equipment used in ice hockey to shoot, pass, and carry the puck across the ice. Ice hockey sticks are approximately 150 - 200 cm long, composed of a long, slender shaft with a flat extension at one end called the blade.",
                     category=category3, user=user2)

session.add(catalogItem1)
session.commit()

catalogItem2 = CatalogItem(name="Mask", description="A goaltender mask, commonly referred to as a goalie mask or a hockey mask, is a mask worn by ice hockey, inline hockey, and field hockey goaltenders to protect the head from injury. Jacques Plante was the first goaltender to create and use a practical mask in 1959.",
                     category=category3, user=user2)

session.add(catalogItem2)
session.commit()

print "Catalog items added!"
