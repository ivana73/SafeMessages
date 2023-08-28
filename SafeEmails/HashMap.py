class HashMap:
    def __init__(self):
        self.map = {}

    def put(self, key, value):
        if key not in self.map:
            self.map[key] = []
        self.map[key].append(value)

    def get(self, key):
        pom = self.map.get(key, [])
        return pom

    def remove(self, key):
        if key in self.map:
            del self.map[key]

    def contains(self, key):
        return key in self.map

    def size(self):
        return len(self.map)

    def keys(self):
        return list(self.map.keys())

    def values(self):
        return list(self.map.values())
