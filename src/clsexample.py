class nothing:
    attr = None

    def __init__(self) -> None:
        pass


    def getAttr(self):
        self.attr = "zhou"

    def useAttr(self):
        new_Attr = self.attr + "shaoqian"
        return new_Attr