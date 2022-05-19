# from django.test import TestCase

# Create your tests here.
# from pytz import timezone


class Abstracttion:
    def __init__(self, name, age):
        self.name = name
        self.age = age 
        
    def my_func(self):
        print("Hello my name is " + self.name + self.age)  
        
class TempCode(Abstracttion):
    def __init__(self, name, age):
        super().__init__(name, age)
        
x = TempCode("Hello, and welcokme! ", 20)        
        
                
x.printMessage()