from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {
           'id': self.id,
           'name': self.name,
           'Items': [{
                'id': item.id,
                'name': item.name,
                'cat_id': item.category_id,
                'description': item.description,
                } for item in self.items]}


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    user_id = Column(Integer, ForeignKey('user.id'))

    category = relationship(Category, back_populates="items")
    user = relationship(User)

    @property
    def serialize(self):
        return {
           'id': self.id,
           'name': self.name,
           'description': self.description,
           'category_id': self.category_id}


Category.items = relationship(
    "Item",
    order_by=Item.id,
    back_populates="category")


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)

