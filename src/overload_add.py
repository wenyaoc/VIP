from mimetypes import init


class adder:
    def __init__(self, val) -> None:
        self.value = val
    
    def __add__(self, other):
        result = adder(self.value)
        result.value += other.value
        return result

    def __sub__(self, other):
        result = adder(self.value)
        result.value = result.value - other.value
        return result
