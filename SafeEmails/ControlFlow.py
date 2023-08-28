class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class ControlFlow(metaclass=Singleton):
    def __init__(self):
        self.last_key = None
        self.last_pass = None
    def get_last_key(self):
        return self.last_key

    def set_last_key(self, k):
        self.last_key = k

    def get_last_pass(self):
        return self.last_pass

    def set_last_pass(self, p):
        self.last_pass = p