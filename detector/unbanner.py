import time


class Unbanner:
    def __init__(self, engine):
        self.engine = engine

    def run(self):
        while True:
            self.engine.unban_expired()
            time.sleep(5)
